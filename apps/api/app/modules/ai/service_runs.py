"""AI run requests, context preview, run reads, the context viewer and usage (M5 phase 7).

The API only builds and freezes the context (`context/builder.py`, in the requester's
tenant session), records the run and publishes its id; it never contacts a provider.

Checks of a run request, in order:
1. AI is on for the platform and the org (`409 ai_disabled`);
2. the provider is available here (`422 provider_unavailable`), enabled with its terms (and,
   for Gemini, the paid-tier attestation) and keyed by an own key or the dev platform key
   (`409 no_provider_enabled`); the model is in its allowlist (`422 model_not_allowed`);
3. the job exists (404) and succeeded (`409 job_not_ready`) and suits the task
   (`422 task_not_applicable`), or the investigation exists (404);
3b. the share policy (M6, `investigations/policy.py`): `409 policy_blocked` with `reason`;
4. per user `AI_RUNS_PER_USER_10MIN` (429);
5. today's DB usage of the org below `daily_token_budget` (`409 budget_exhausted`, RT9);
6. build the context (`ContextBuildError` -> 409 / 422);
7. `runs.create_run`: per-org lock, dedupe, per-org and global active caps counting
   children (`409 ai_busy`, RT8), rows + audit in the request transaction.
The route commits, then `runs.dispatch` publishes (children first); a lost publish still
answers 202 (`ai.resume` re-sends).
"""

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Any, Literal

from pydantic import ValidationError
from sqlalchemy import func, select
from starlette.requests import HTTPConnection

from app.core import rate_limit
from app.core.config import Settings, get_settings
from app.core.errors import AppError, Conflict, Forbidden, NotFound
from app.core.pagination import PageParams
from app.core.rbac import OrgContext, Permission
from app.modules.ai import repository, runs, service_outputs, service_settings
from app.modules.ai.availability import provider_available
from app.modules.ai.catalog import AI_CATALOG
from app.modules.ai.context import builder
from app.modules.ai.contracts import (
    PENDING_TASKS,
    AiProviderName,
    AiRunRequest,
    AiRunStatus,
    AiScope,
    AiTask,
    ContextBuildError,
    ContextItem,
    ContextStats,
    FrozenContext,
    OutputFlag,
    RefKind,
    RunMetrics,
)
from app.modules.ai.models import AiOrgSettings, AiRun
from app.modules.ai.schemas import (
    AiChildRunOut,
    AiContextPreviewOut,
    AiContextStageOut,
    AiInclusions,
    AiProviderUsageOut,
    AiRunContextOut,
    AiRunCreated,
    AiRunDetail,
    AiRunOut,
    AiRunPage,
    AiTokenUsage,
    AiUsageOut,
)
from app.modules.ai.service_providers import ModelNotAllowed, ProviderUnavailable, keyed
from app.modules.analysis.models import AnalysisJob, AnalysisStatus, Analyzer
from app.modules.audit import service as audit
from app.modules.investigations import policy
from app.modules.investigations.models import Investigation

PREVIEWS_PER_USER_PER_10MIN = 30
_TARGET_KINDS: dict[str, Literal["finding", "alert", "function"]] = {
    "finding": "finding",
    "alert": "alert",
    "function": "function",
}
_ANALYZER_TASKS = {
    AiTask.SUMMARIZE_PCAP: Analyzer.PCAP,
    AiTask.EXPLAIN_STATIC: Analyzer.STATIC,
    AiTask.EXPLAIN_FUNCTION: Analyzer.REVERSE,
}
# Kind -> the category of data that would leave the platform (shown before a run).
_CATEGORIES: dict[RefKind, str] = {
    RefKind.JOB: "job_summary",
    RefKind.FINDING: "finding_text",
    RefKind.ALERT: "alert_text",
    RefKind.FLOW: "network_flows",
    RefKind.RECORD: "network_records",
    RefKind.IOC: "indicators",
    RefKind.TI_RESULT: "threat_intel_results",
    RefKind.SAMPLE: "file_facts",
    RefKind.PE_SUMMARY: "file_facts",
    RefKind.SIGNATURE: "signature_matches",
    RefKind.CAPABILITY: "capabilities",
    RefKind.STRING: "strings",
    RefKind.TIMELINE: "timeline",
    RefKind.EVIDENCE: "evidence_metadata",
    RefKind.INVESTIGATION: "case_text",
    RefKind.DIGEST_CLAIM: "digest_claims",
    RefKind.FUNCTION: "function_facts",  # M10
    RefKind.CODE: "decompiled_code",  # M10
}


class AiDisabled(Conflict):
    code = "ai_disabled"
    message = "AI analysis is off for this organization"


class NoProviderEnabled(Conflict):
    code = "no_provider_enabled"
    message = "The AI provider is not enabled (with its terms acknowledged and a key)"


class JobNotReady(Conflict):
    code = "job_not_ready"
    message = "Only a succeeded analysis can be analyzed"


class BudgetExhausted(Conflict):
    code = "budget_exhausted"
    message = "Today's AI token budget of this organization is spent"


class TargetNotFound(AppError):
    status_code = 422
    code = "target_not_found"
    message = "The finding or alert is not part of this analysis"


class TaskNotApplicable(AppError):
    status_code = 422
    code = "task_not_applicable"
    message = "This task does not apply to the selected analysis"


class ContextEmpty(AppError):
    status_code = 422
    code = "context_empty"
    message = "There is no evidence to analyze"


_BUILD_ERRORS: dict[str, type[AppError]] = {
    "job_not_ready": JobNotReady,
    "target_not_found": TargetNotFound,
    "task_not_applicable": TaskNotApplicable,
    "context_empty": ContextEmpty,
}


# --- request checks ------------------------------------------------------------------


async def _enabled_settings(ctx: OrgContext) -> AiOrgSettings:
    row = await repository.org_settings(ctx.session, ctx.org_id)
    if not get_settings().ai_enabled or row is None or not row.ai_enabled:
        raise AiDisabled()
    return row


async def _provider_and_model(
    ctx: OrgContext, req: AiRunRequest, row: AiOrgSettings, settings: Settings
) -> tuple[AiProviderName, str]:
    provider = req.provider or (
        AiProviderName(row.default_provider) if row.default_provider else None
    )
    provider = provider or settings.ai_default_provider
    available, _ = provider_available(settings, provider)
    if not available:
        raise ProviderUnavailable()
    config = await repository.provider_config(ctx.session, ctx.org_id, provider.value)
    entry = AI_CATALOG[provider]
    if (
        config is None
        or not config.enabled
        or config.terms_ack_at is None
        or (entry.requires_billing_flag and config.paid_tier_ack_at is None)
        or not keyed(config, settings, provider)
    ):
        raise NoProviderEnabled()
    model = req.model or config.model or entry.default_model
    if model not in entry.model_ids:
        raise ModelNotAllowed()
    return provider, model


async def _check_target(ctx: OrgContext, req: AiRunRequest) -> None:
    if req.job_id is not None:
        job = (
            await ctx.session.execute(
                select(AnalysisJob.status, AnalysisJob.analyzer).where(
                    AnalysisJob.id == req.job_id, AnalysisJob.organization_id == ctx.org_id
                )
            )
        ).one_or_none()
        if job is None:
            raise NotFound()
        status, analyzer = job
        if status != AnalysisStatus.SUCCEEDED:
            raise JobNotReady()
        wanted = _ANALYZER_TASKS.get(req.task)
        if wanted is not None and analyzer != wanted:
            raise TaskNotApplicable()
    else:
        found = await ctx.session.scalar(
            select(Investigation.id).where(
                Investigation.id == req.investigation_id,
                Investigation.organization_id == ctx.org_id,
            )
        )
        if found is None:
            raise NotFound()


async def _check_policy(ctx: OrgContext, req: AiRunRequest) -> None:
    """M6 (RT20): the case / evidence share policy. A job-scope run is refused when its
    evidence or its case excludes AI (or the case is TLP:RED); a case-scope run when the
    case does (its excluded evidence items are skipped by the builder instead)."""
    if req.job_id is not None:
        found = await policy.load_policy(ctx.session, ctx.org_id, job_ids=(req.job_id,))
    else:
        found = await policy.load_policy(
            ctx.session, ctx.org_id, investigation_id=req.investigation_id
        )
    policy.raise_if_ai_blocked(found)


async def _check_budget(ctx: OrgContext, row: AiOrgSettings) -> None:
    if await repository.tokens_today(ctx.session, ctx.org_id) >= row.daily_token_budget:
        raise BudgetExhausted()


async def _prepare(
    ctx: OrgContext, body: AiRunRequest, rate_key: str, limit: int
) -> tuple[AiOrgSettings, AiRunRequest, AiProviderName, str]:
    if body.task in PENDING_TASKS:
        # M10: `explain_function` is a frozen value; its run path lands in phase 9.
        raise TaskNotApplicable()
    settings = get_settings()
    row = await _enabled_settings(ctx)
    provider, model = await _provider_and_model(ctx, body, row, settings)
    await _check_target(ctx, body)
    await _check_policy(ctx, body)
    await rate_limit.hit(rate_key, limit, 600)
    # A plain AiRunRequest with the resolved provider and model (never the HTTP subclass).
    req = AiRunRequest.model_validate({**body.model_dump(), "provider": provider, "model": model})
    return row, req, provider, model


def _build_error(exc: ContextBuildError) -> AppError:
    return _BUILD_ERRORS.get(exc.code, ContextEmpty)()


# --- run creation and preview --------------------------------------------------------


async def request_run(
    ctx: OrgContext, body: AiRunRequest, request: HTTPConnection
) -> tuple[AiRunCreated, list[uuid.UUID]]:
    """Create (not committed yet) or deduplicate. Returns the body and the run ids to
    dispatch after the commit (children first, then the parent; empty when deduplicated)."""
    settings = get_settings()
    row, req, _, _ = await _prepare(
        ctx, body, f"ai:runs:{ctx.user.id}", settings.ai_runs_per_user_10min
    )
    await _check_budget(ctx, row)
    try:
        built = await builder.build_run(ctx.session, ctx.org_id, ctx.user.id, req, row)
    except ContextBuildError as exc:
        raise _build_error(exc) from None
    run, deduplicated = await runs.create_run_for_request(
        ctx.session, ctx.org_id, ctx.user.id, req, built, request
    )
    out = AiRunCreated(run=await get_run_out(ctx, run.id), deduplicated=deduplicated)
    if deduplicated:
        return out, []
    children = await ctx.session.scalars(
        select(AiRun.id)
        .where(AiRun.organization_id == ctx.org_id, AiRun.parent_run_id == run.id)
        .order_by(AiRun.created_at, AiRun.id)
    )
    return out, [*children, run.id]


def categories(items: Sequence[ContextItem]) -> list[str]:
    return sorted({_CATEGORIES[item.kind] for item in items})


async def preview(ctx: OrgContext, body: AiRunRequest) -> AiContextPreviewOut:
    """What a run would send. Nothing is persisted or audited; refused while AI is off."""
    row, req, provider, model = await _prepare(
        ctx, body, f"ai:preview:{ctx.user.id}", PREVIEWS_PER_USER_PER_10MIN
    )
    try:
        ctx_ = await builder.preview(ctx.session, ctx.org_id, ctx.user.id, req, row)
    except ContextBuildError as exc:
        raise _build_error(exc) from None
    return AiContextPreviewOut(
        task=req.task,
        provider=provider,
        model=model,
        context_sha256=ctx_.sha256,
        context_stats=ctx_.stats,
        items=list(ctx_.items),
        categories=categories(ctx_.items),
        inclusions=AiInclusions(
            pseudonymize_internal=row.pseudonymize_internal,
            include_strings=row.include_strings,
            include_ti=row.include_ti,
            include_case_text=row.include_case_text,
        ),
    )


# --- reads ---------------------------------------------------------------------------


def _usage(raw: dict[str, Any] | None) -> AiTokenUsage:
    values = {}
    for key in ("input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens"):
        value = (raw or {}).get(key)
        values[key] = value if isinstance(value, int) and value >= 0 else 0
    return AiTokenUsage(**values, total_tokens=sum(values.values()))


def _metrics(raw: dict[str, Any] | None) -> RunMetrics | None:
    if not raw:
        return None
    try:
        return RunMetrics.model_validate(raw)
    except ValidationError:
        return None


def _stats(raw: dict[str, Any] | None) -> ContextStats | None:
    try:
        return ContextStats.model_validate(raw or {})
    except ValidationError:
        return None


def _run_out(run: AiRun, resume_at: datetime | None, requester: str, children: int) -> AiRunOut:
    metrics = _metrics(run.metrics)
    return AiRunOut(
        id=run.id,
        task=AiTask(run.task),
        scope=AiScope(run.scope),
        job_id=run.job_id,
        investigation_id=run.investigation_id,
        target_kind=_TARGET_KINDS.get(run.target_kind or ""),
        target_id=run.target_id,
        parent_run_id=run.parent_run_id,
        supersedes_run_id=run.supersedes_run_id,
        provider=AiProviderName(run.provider),
        model=run.model,
        served_model=run.served_model,
        prompt_version=run.prompt_version,
        output_schema=run.output_schema,
        status=AiRunStatus(run.status),
        error_code=run.error_code,
        refusal_category=metrics.refusal_category if metrics else None,
        context_sha256=run.context_sha256,
        deadline_at=run.deadline_at,
        resume_at=resume_at,
        usage=_usage(run.usage),
        cost_micros=run.cost_micros,
        cost_estimated=True,
        price_version=run.price_version,
        citation_accuracy=metrics.citation_accuracy if metrics else None,
        claims_unsupported=metrics.claims_unsupported if metrics else None,
        children=children,
        requested_by=run.requested_by,
        requested_by_name=requester,
        created_at=run.created_at,
        started_at=run.started_at,
        finished_at=run.finished_at,
    )


async def get_run_out(ctx: OrgContext, run_id: uuid.UUID) -> AiRunOut:
    row = await repository.get_run_row(ctx.session, ctx.org_id, run_id)
    if row is None:
        raise NotFound()
    counts = await repository.child_counts(ctx.session, ctx.org_id, [run_id])
    return _run_out(row[0], row[1], row[2], counts.get(run_id, 0))


async def list_runs(
    ctx: OrgContext,
    page: PageParams,
    *,
    job_id: uuid.UUID | None,
    investigation_id: uuid.UUID | None,
    task: AiTask | None,
    status: AiRunStatus | None,
    target_id: uuid.UUID | None,
) -> AiRunPage:
    """Top-level runs (incident children are listed in their parent), newest first."""
    where = [AiRun.organization_id == ctx.org_id, AiRun.parent_run_id.is_(None)]
    if job_id is not None:
        where.append(AiRun.job_id == job_id)
    if investigation_id is not None:
        where.append(AiRun.investigation_id == investigation_id)
    if task is not None:
        where.append(AiRun.task == task.value)
    if status is not None:
        where.append(AiRun.status == status.value)
    if target_id is not None:
        where.append(AiRun.target_id == target_id)
    total = await ctx.session.scalar(select(func.count(AiRun.id)).where(*where))
    rows = (
        await ctx.session.execute(
            repository.runs_query()
            .where(*where)
            .order_by(AiRun.created_at.desc(), AiRun.id)
            .limit(page.limit)
            .offset(page.offset)
        )
    ).all()
    counts = await repository.child_counts(ctx.session, ctx.org_id, [r[0].id for r in rows])
    items = [_run_out(r[0], r[1], r[2], counts.get(r[0].id, 0)) for r in rows]
    return AiRunPage(items=items, total=int(total or 0))


async def _pseudonym_map(ctx: OrgContext, run: AiRun) -> dict[str, str]:
    """The run tree's own map (consistent across an incident's runs; never another org's)."""
    tree = await repository.tree_run_ids(ctx.session, ctx.org_id, run)
    merged: dict[str, str] = {}
    for item in await repository.inputs_of(ctx.session, ctx.org_id, tree):
        for key, value in (item.pseudonym_map or {}).items():
            if isinstance(key, str) and isinstance(value, str):
                merged.setdefault(key, value)
    return merged


def _flags(raw: Sequence[Any]) -> list[OutputFlag]:
    out = []
    for value in raw or ():
        try:
            out.append(OutputFlag(value))
        except ValueError:
            continue
    return out


def _may_reverse(ctx: OrgContext) -> bool:
    """Showing original internal values (reversed pseudonyms, the map) needs `evidence.write`."""
    return Permission.EVIDENCE_WRITE in ctx.permissions  # M11 RT1: role ∩ key scopes


async def get_run(
    ctx: OrgContext, run_id: uuid.UUID, *, keep_pseudonyms: bool | None = None
) -> AiRunDetail:
    """The run and its output read model. Pseudonyms are reversed to the original internal
    values for `evidence.write` members only (the default for them unless `keep`); a viewer
    always gets them kept as sent, and an explicit reverse request from one is a 403."""
    may_reverse = _may_reverse(ctx)
    if keep_pseudonyms is False and not may_reverse:
        raise Forbidden()
    keep = not may_reverse if keep_pseudonyms is None else keep_pseudonyms
    found = await repository.get_run_row(ctx.session, ctx.org_id, run_id)
    if found is None:
        raise NotFound()
    run, resume_at, requester = found
    children = await repository.children_of(ctx.session, ctx.org_id, run.id)
    base = _run_out(run, resume_at, requester, len(children))
    output = await repository.output_of(ctx.session, ctx.org_id, run.id)
    flags = _flags(output.flags) if output is not None else []
    withheld = run.error_code == "canary_leak" or (
        output is not None and service_outputs.has_canary_leak(output)
    )
    body = None
    final_ok = run.status in (AiRunStatus.COMPLETED.value, AiRunStatus.PARTIAL.value)
    if output is not None and final_ok and not withheld:
        rows = await repository.citations_of(ctx.session, ctx.org_id, output.id)
        links = await service_outputs.LinkContext.load(ctx.session, ctx.org_id, rows)
        mapping = {} if keep else await _pseudonym_map(ctx, run)
        times = await service_outputs.timeline_times(ctx.session, ctx.org_id, run.id, rows)
        body = service_outputs.build(
            output, rows, links, mapping, keep_pseudonyms=keep, times=times
        )
    child_runs = []
    for child, child_flags in children:
        child_metrics = _metrics(child.metrics)
        child_runs.append(
            AiChildRunOut(
                id=child.id,
                job_id=child.job_id,
                status=AiRunStatus(child.status),
                error_code=child.error_code,
                refusal_category=child_metrics.refusal_category if child_metrics else None,
                flags=_flags(child_flags),
                citation_accuracy=child_metrics.citation_accuracy if child_metrics else None,
                usage=_usage(child.usage),
                finished_at=child.finished_at,
            )
        )
    return AiRunDetail(
        **base.model_dump(),
        context_stats=_stats(run.context_stats),
        metrics=_metrics(run.metrics),
        flags=flags,
        child_runs=child_runs,
        output=body,
        output_withheld=withheld,
    )


async def get_context(
    ctx: OrgContext, run_id: uuid.UUID, *, reveal: bool, request: HTTPConnection | None = None
) -> AiRunContextOut:
    """The frozen context(s) exactly as sent (base, and reduce for an incident parent);
    `reveal` adds the pseudonym map (never sent to a provider) and is audited
    (`ai.context_revealed`: the run and the actor, never a name; the caller commits).
    Revealing needs `evidence.write` (analyst and up): a viewer reads the pseudonymized
    context only (403 otherwise)."""
    if reveal and not _may_reverse(ctx):
        raise Forbidden()
    found = await repository.get_run_row(ctx.session, ctx.org_id, run_id)
    if found is None:
        raise NotFound()
    run = found[0]
    stages = []
    for item in await repository.inputs_of(ctx.session, ctx.org_id, [run.id]):
        stored = dict(item.context or {})
        try:
            frozen = FrozenContext.model_validate({**stored, "pseudonym_map": {}})
        except ValidationError:
            continue
        stages.append(
            AiContextStageOut(
                stage="reduce" if item.stage == "reduce" else "base",
                context_sha256=item.context_sha256,
                version=frozen.version,
                task=frozen.task,
                items=list(frozen.items),
                stats=frozen.stats,
                pseudonym_map=dict(item.pseudonym_map or {}) if reveal else None,
            )
        )
    stages.sort(key=lambda s: 0 if s.stage == "base" else 1)
    if reveal:
        audit.record(
            ctx.session,
            action="ai.context_revealed",
            org_id=ctx.org_id,
            actor_id=ctx.user.id,
            target_type="ai_run",
            target_id=run.id,
            details={"stages": [s.stage for s in stages]},
            request=request,
        )
    return AiRunContextOut(
        run_id=run.id, context_sha256=run.context_sha256, revealed=reveal, stages=stages
    )


async def usage(ctx: OrgContext) -> AiUsageOut:
    settings = get_settings()
    row, _ = await service_settings.effective(ctx)
    providers = []
    total = 0
    cost = 0
    for provider, count, tokens, cost_micros in await repository.usage_today(
        ctx.session, ctx.org_id
    ):
        try:
            name = AiProviderName(provider)
        except ValueError:
            continue
        usage_out = AiTokenUsage(**tokens, total_tokens=sum(tokens.values()))
        providers.append(
            AiProviderUsageOut(provider=name, runs=count, usage=usage_out, cost_micros=cost_micros)
        )
        total += usage_out.total_tokens
        cost += cost_micros
    return AiUsageOut(
        day=repository.day_start().date(),
        providers=providers,
        total_tokens=total,
        cost_micros=cost,
        daily_token_budget=row.daily_token_budget,
        remaining_tokens=max(row.daily_token_budget - total, 0),
        run_token_cap=row.run_token_cap,
        incident_token_cap=row.incident_token_cap,
        ceilings=service_settings.ceilings(settings),
    )
