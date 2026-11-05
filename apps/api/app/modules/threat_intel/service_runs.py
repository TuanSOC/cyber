"""Enrichment run requests (job and manual lookup) and run reads (M4 phase 5).

Creation goes through `runs.create_run` (phase 2) inside one org session: the run, its index
row, its planned items and the `ti.enrichment_requested` audit row commit together, and
`runs.dispatch` publishes `ti.enrich` only after the commit. A lost publish is left to
`ti.resume` (the run stays queued with its `dispatched_at`), so the request still answers 202.

Caps: per user 30 requests per 10 minutes (429), per org 3 active runs and 20 active runs
globally (409 `enrichment_busy`); creation is serialized per org (advisory lock), so the
per-org cap and the job dedupe cannot be raced past. The global cap check and the insert run
under a second, global advisory lock, always taken after the org one (one lock order), held
until the commit: two orgs cannot both pass a count of 19 active runs.
"""

import logging
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, cast

from sqlalchemy import Select, func, select, text
from starlette.requests import HTTPConnection

from app.core import rate_limit
from app.core.config import get_settings
from app.core.deps import CurrentUser
from app.core.errors import AppError, Conflict, NotFound
from app.core.pagination import PageParams
from app.core.rbac import OrgContext, Permission, org_session
from app.core.tenancy import tenant_session
from app.modules.analysis.models import AnalysisJob, AnalysisStatus
from app.modules.audit import service as audit
from app.modules.investigations import policy
from app.modules.threat_intel import runs
from app.modules.threat_intel.availability import provider_available
from app.modules.threat_intel.catalog import CATALOG
from app.modules.threat_intel.models import (
    RUN_ACTIVE,
    TiEnrichmentRun,
    TiProviderConfig,
    TiResult,
    TiRunIndex,
    TiRunItem,
)
from app.modules.threat_intel.providers.base import IocType, ProviderName
from app.modules.threat_intel.schemas import (
    ItemReason,
    ItemState,
    LookupCreate,
    RunDetailOut,
    RunItemOut,
    RunItemPage,
    RunOut,
    RunPage,
    RunRequestOut,
    RunStatus,
    ValueReportOut,
)
from app.modules.threat_intel.service_integrations import ProviderUnavailable
from app.modules.threat_intel.service_results import result_out
from app.modules.users.models import User

log = logging.getLogger(__name__)

RUNS_PER_USER_PER_10MIN = 30
MAX_ACTIVE_RUNS_PER_ORG = 3
MAX_ACTIVE_RUNS_GLOBAL = 20
GLOBAL_RUNS_LOCK = "ti-runs:global"


class JobNotReady(Conflict):
    code = "job_not_ready"
    message = "Only a succeeded analysis can be enriched"


class EnrichmentBusy(Conflict):
    code = "enrichment_busy"
    message = "Too many enrichment runs are active, try again when one has finished"


class NoProviderEnabled(Conflict):
    code = "no_provider_enabled"
    message = "No threat intel provider is enabled for this organization"


class ProviderNotEnabled(Conflict):
    code = "provider_not_enabled"
    message = "A requested provider is not enabled for this organization"


class TooManyValues(AppError):
    status_code = 422
    code = "too_many_values"
    message = "Too many values for one lookup"


class NoValues(AppError):
    status_code = 422
    code = "no_values"
    message = "At least one value is required"


class UnknownProvider(AppError):
    status_code = 422
    code = "unknown_provider"
    message = "Unknown provider"


_RUN_ERRORS: dict[str, type[AppError]] = {
    "provider_unavailable": ProviderUnavailable,
    "no_provider_enabled": NoProviderEnabled,
    "provider_not_enabled": ProviderNotEnabled,
    "too_many_values": TooManyValues,
    "no_values": NoValues,
    "unknown_provider": UnknownProvider,
    "job_not_found": NotFound,
}


@dataclass(frozen=True)
class _Created:
    out: RunRequestOut
    run_id: uuid.UUID | None


# --- reads ---------------------------------------------------------------------------


def _runs_query() -> Select[TiEnrichmentRun, datetime | None, str]:
    return (
        select(TiEnrichmentRun, TiRunIndex.resume_at, User.display_name)
        .outerjoin(
            TiRunIndex,
            (TiRunIndex.run_id == TiEnrichmentRun.id)
            & (TiRunIndex.organization_id == TiEnrichmentRun.organization_id),
        )
        .join(User, User.id == TiEnrichmentRun.requested_by)
    )


def _run_out(run: TiEnrichmentRun, resume_at: datetime | None, requester: str) -> RunOut:
    return RunOut(
        id=run.id,
        scope="job" if run.scope == "job" else "manual",
        job_id=run.job_id,
        status=cast(RunStatus, run.status),  # DB check constraint
        providers=list(run.providers),
        summary=dict(run.summary or {}),
        deadline_at=run.deadline_at,
        resume_at=resume_at,
        requested_by=run.requested_by,
        requested_by_name=requester,
        created_at=run.created_at,
        started_at=run.started_at,
        finished_at=run.finished_at,
    )


async def _get_run_out(ctx: OrgContext, run_id: uuid.UUID) -> RunOut:
    row = (
        await ctx.session.execute(
            _runs_query().where(
                TiEnrichmentRun.id == run_id, TiEnrichmentRun.organization_id == ctx.org_id
            )
        )
    ).one_or_none()
    if row is None:
        raise NotFound()
    return _run_out(row[0], row[1], row[2])


async def list_runs(
    ctx: OrgContext,
    page: PageParams,
    *,
    job_id: uuid.UUID | None,
    status: RunStatus | None,
) -> RunPage:
    where = [TiEnrichmentRun.organization_id == ctx.org_id]
    if job_id is not None:
        where.append(TiEnrichmentRun.job_id == job_id)
    if status is not None:
        where.append(TiEnrichmentRun.status == status)
    total = await ctx.session.scalar(select(func.count(TiEnrichmentRun.id)).where(*where))
    rows = await ctx.session.execute(
        _runs_query()
        .where(*where)
        .order_by(TiEnrichmentRun.created_at.desc(), TiEnrichmentRun.id)
        .limit(page.limit)
        .offset(page.offset)
    )
    return RunPage(items=[_run_out(r[0], r[1], r[2]) for r in rows], total=int(total or 0))


async def get_run(
    ctx: OrgContext,
    run_id: uuid.UUID,
    page: PageParams,
    *,
    provider: ProviderName | None,
    state: ItemState | None,
) -> RunDetailOut:
    run = await _get_run_out(ctx, run_id)
    where = [TiRunItem.run_id == run_id, TiRunItem.organization_id == ctx.org_id]
    if provider is not None:
        where.append(TiRunItem.provider == provider.value)
    if state is not None:
        where.append(TiRunItem.state == state)
    total = await ctx.session.scalar(select(func.count()).select_from(TiRunItem).where(*where))
    rows = await ctx.session.execute(
        select(TiRunItem, TiResult)
        .outerjoin(
            TiResult,
            (TiResult.id == TiRunItem.result_id)
            & (TiResult.organization_id == TiRunItem.organization_id),
        )
        .where(*where)
        .order_by(TiRunItem.seq)
        .limit(page.limit)
        .offset(page.offset)
    )
    now = datetime.now(UTC)
    items = [
        RunItemOut(
            seq=item.seq,
            provider=ProviderName(item.provider),
            ioc_type=IocType(item.ioc_type),
            value_norm=item.value_norm,
            ioc_key=item.ioc_key,
            # DB check constraints hold these to the literal sets.
            state=cast(ItemState, item.state),
            reason=cast(ItemReason | None, item.reason),
            result=result_out(result, now) if result is not None else None,
            from_cache=result is not None and result.run_id != run_id,
        )
        for item, result in rows
    ]
    return RunDetailOut(**run.model_dump(), items=RunItemPage(items=items, total=int(total or 0)))


# --- creation ------------------------------------------------------------------------


async def _lock_org_runs(ctx: OrgContext) -> None:
    await ctx.session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": f"ti-runs:{ctx.org_id}"},
    )


async def _lock_global_runs(ctx: OrgContext) -> None:
    """Taken after `_lock_org_runs` only (never the reverse), held through the insert."""
    await ctx.session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
        {"key": GLOBAL_RUNS_LOCK},
    )


async def _global_busy() -> bool:
    async with tenant_session(None, None) as session:
        active = await session.scalar(
            select(func.count()).select_from(TiRunIndex).where(TiRunIndex.status.in_(RUN_ACTIVE))
        )
    return int(active or 0) >= MAX_ACTIVE_RUNS_GLOBAL


async def _check_org_busy(ctx: OrgContext) -> None:
    active = await ctx.session.scalar(
        select(func.count(TiEnrichmentRun.id)).where(
            TiEnrichmentRun.organization_id == ctx.org_id,
            TiEnrichmentRun.status.in_(RUN_ACTIVE),
        )
    )
    if int(active or 0) >= MAX_ACTIVE_RUNS_PER_ORG:
        raise EnrichmentBusy()


async def _default_providers(ctx: OrgContext) -> list[ProviderName]:
    """Every enabled provider with a key that this deployment allows, in catalog order."""
    settings = get_settings()
    enabled = set(
        (
            await ctx.session.scalars(
                select(TiProviderConfig.provider).where(
                    TiProviderConfig.organization_id == ctx.org_id,
                    TiProviderConfig.enabled.is_(True),
                    TiProviderConfig.key_ct.is_not(None),
                )
            )
        ).all()
    )
    names = [n for n in CATALOG if n.value in enabled and provider_available(n, settings)]
    if not names:
        raise NoProviderEnabled()
    return names


def _report(report: Sequence[runs.ValueReport]) -> list[ValueReportOut]:
    return [
        ValueReportOut(
            index=r.index,
            ioc_type=r.ioc_type,
            value_norm=r.value_norm,
            ioc_key=r.ioc_key,
            notes=list(r.notes),
            skipped=r.skipped,
            providers=list(r.providers),
            provider_skips=dict(r.provider_skips),
        )
        for r in report
    ]


def _counts(summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "items": summary.get("items", 0),
        "planned_values": summary.get("planned_values", 0),
        "duplicates": summary.get("duplicates", 0),
        "truncated": summary.get("truncated", False),
        "skipped": summary.get("skipped", {}),
    }


async def _create(
    ctx: OrgContext,
    request: HTTPConnection,
    *,
    scope: str,
    providers: list[ProviderName] | None,
    job_id: uuid.UUID | None = None,
    values: list[runs.LookupValue] | None = None,
) -> _Created:
    await rate_limit.hit(f"ti:runs:{ctx.user.id}", RUNS_PER_USER_PER_10MIN, 600)
    await _lock_org_runs(ctx)
    if job_id is not None:
        job_status = await ctx.session.scalar(
            select(AnalysisJob.status).where(
                AnalysisJob.id == job_id, AnalysisJob.organization_id == ctx.org_id
            )
        )
        if job_status is None:
            raise NotFound()
        if job_status != AnalysisStatus.SUCCEEDED:
            raise JobNotReady()
        # M6 (RT20): the job's evidence and case may exclude threat intel (or be TLP:RED).
        policy.raise_if_ti_blocked(
            await policy.load_policy(ctx.session, ctx.org_id, job_ids=(job_id,))
        )
        existing = (
            await ctx.session.execute(
                _runs_query()
                .where(
                    TiEnrichmentRun.organization_id == ctx.org_id,
                    TiEnrichmentRun.job_id == job_id,
                    TiEnrichmentRun.status.in_(RUN_ACTIVE),
                )
                .order_by(TiEnrichmentRun.created_at.desc())
                .limit(1)
            )
        ).first()
        if existing is not None:
            run = _run_out(existing[0], existing[1], existing[2])
            items = int(run.summary.get("items", 0) or 0)
            out = RunRequestOut(
                run=run, deduplicated=True, items=items, summary=run.summary, report=[]
            )
            return _Created(out, None)
    await _check_org_busy(ctx)
    await _lock_global_runs(ctx)
    if await _global_busy():
        raise EnrichmentBusy()
    names = providers or await _default_providers(ctx)
    try:
        created = await runs.create_run(
            ctx.session,
            ctx.org_id,
            scope,
            job_id=job_id,
            values=values,
            providers=names,
            requested_by=ctx.user.id,
        )
    except runs.RunError as exc:
        raise _RUN_ERRORS.get(exc.code, AppError)() from None
    report = _report(created.report)
    if created.run_id is None:
        out = RunRequestOut(
            run=None, deduplicated=False, items=0, summary=created.summary, report=report
        )
        return _Created(out, None)

    audit.record(
        ctx.session,
        action="ti.enrichment_requested",
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        target_type="ti_run",
        target_id=created.run_id,
        details={
            "scope": scope,
            "job_id": str(job_id) if job_id else None,
            "providers": [p.value for p in names],
            **_counts(created.summary),
        },
        request=request,
    )
    await ctx.session.flush()
    out = RunRequestOut(
        run=await _get_run_out(ctx, created.run_id),
        deduplicated=False,
        items=created.items,
        summary=created.summary,
        report=report,
    )
    return _Created(out, created.run_id)


async def _request(
    org_id: uuid.UUID,
    user: CurrentUser,
    request: HTTPConnection,
    **kwargs: Any,
) -> tuple[RunRequestOut, bool]:
    """Create (committed), then publish. Returns the body and whether a run was created."""
    async with org_session(org_id, user, Permission.EVIDENCE_WRITE) as ctx:
        created = await _create(ctx, request, **kwargs)
    if created.run_id is None:
        return created.out, False
    # Committed: nothing below may turn this request into an error (ti.resume re-sends).
    if not await runs.dispatch(created.run_id, org_id):
        log.warning("ti run %s committed but not published; left to ti.resume", created.run_id)
    return created.out, True


async def request_job_enrichment(
    org_id: uuid.UUID,
    user: CurrentUser,
    job_id: uuid.UUID,
    providers: list[ProviderName] | None,
    request: HTTPConnection,
) -> tuple[RunRequestOut, bool]:
    return await _request(org_id, user, request, scope="job", job_id=job_id, providers=providers)


async def request_lookup(
    org_id: uuid.UUID, user: CurrentUser, body: LookupCreate, request: HTTPConnection
) -> tuple[RunRequestOut, bool]:
    values = [
        runs.LookupValue(v.value, v.type.value if v.type is not None else None) for v in body.values
    ]
    return await _request(
        org_id, user, request, scope="manual", values=values, providers=body.providers
    )
