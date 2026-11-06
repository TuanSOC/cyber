"""Run creation and dispatch (signatures FROZEN in phase 1; filled by phase 7).

`create_run` writes, in the caller's transaction: `ai_runs` (+ incident children with
`parent_run_id`, task `job_digest` and the parent's deadline), `ai_run_index`,
`ai_run_inputs` (stage `base`), `ai_context_refs` and the `ai.run_requested` audit row (no
content). It returns `(root run, deduplicated)`. `dispatch` publishes `ai.run` after the
commit (children first, then the parent); a publish failure is recovered by `ai.resume`.

Serialization (the M4 pattern): creation takes the per-org advisory lock, so the dedupe
lookup and the per-org cap cannot be raced past, then, only when a run will be created, the
global advisory lock (always in that order), held until the commit, around the global count.
Both caps count every non-final run, incident children included, and a request needs room
for every run it creates (1, or 1 + children for an incident; RT8).
"""

import logging
import uuid
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import anyio
from cyberlab_jobs import AI_RUN, Queues
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import HTTPConnection

from app.core.config import get_settings
from app.core.errors import Conflict
from app.core.tenancy import tenant_session
from app.core.threads import broker_limiter
from app.modules.ai import repository
from app.modules.ai.catalog import AI_CATALOG
from app.modules.ai.contracts import (
    RUN_ACTIVE,
    AiProviderName,
    AiRunRequest,
    AiRunStatus,
    AiScope,
    AiTask,
    BuiltRun,
    FrozenContext,
)
from app.modules.ai.messages import AiRunMessage
from app.modules.ai.models import AiContextRef, AiRun, AiRunIndex, AiRunInput
from app.modules.ai.output_schema import OUTPUT_SCHEMA_VERSION
from app.modules.ai.prompt import PROMPT_VERSION
from app.modules.audit import service as audit

log = logging.getLogger(__name__)

SEND_TIMEOUT_S = 15
GLOBAL_RUNS_LOCK = "ai-runs:global"
# Runs an identical request is deduplicated against (RT: active or completed).
DEDUPE_STATUSES = (*RUN_ACTIVE, AiRunStatus.COMPLETED)
_TARGET_KINDS = {
    AiTask.EXPLAIN_FINDING: "finding",
    AiTask.EXPLAIN_ALERT: "alert",
    AiTask.EXPLAIN_FUNCTION: "function",  # M10 (an re_functions id; 0018 check)
}


class AiBusy(Conflict):
    code = "ai_busy"
    message = "Too many AI analyses are active, try again when one has finished"


def org_lock_key(org_id: uuid.UUID) -> str:
    return f"ai-runs:{org_id}"


async def _global_active() -> int:
    """Non-final runs of every org (system lookup; no tenant data)."""
    async with tenant_session(None, None) as session:
        active = await session.scalar(
            select(func.count()).select_from(AiRunIndex).where(AiRunIndex.status.in_(RUN_ACTIVE))
        )
    return int(active or 0)


async def _identical(
    session: AsyncSession,
    org_id: uuid.UUID,
    req: AiRunRequest,
    provider: str,
    model: str,
    context_sha256: str,
    statuses: Sequence[str] | None,
) -> AiRun | None:
    where = [
        AiRun.organization_id == org_id,
        AiRun.parent_run_id.is_(None),
        AiRun.task == req.task.value,
        AiRun.provider == provider,
        AiRun.model == model,
        AiRun.prompt_version == PROMPT_VERSION,
        AiRun.context_sha256 == context_sha256,
        AiRun.job_id.is_(None) if req.job_id is None else AiRun.job_id == req.job_id,
        AiRun.investigation_id.is_(None)
        if req.investigation_id is None
        else AiRun.investigation_id == req.investigation_id,
        AiRun.target_id.is_(None) if req.target_id is None else AiRun.target_id == req.target_id,
    ]
    if statuses is not None:
        where.append(AiRun.status.in_(statuses))
    return await session.scalar(
        select(AiRun).where(*where).order_by(AiRun.created_at.desc(), AiRun.id).limit(1)
    )


def _resolve(req: AiRunRequest) -> tuple[str, str]:
    """The provider and model of the run (the routes pass both resolved)."""
    provider = req.provider or get_settings().ai_default_provider
    model = req.model or AI_CATALOG[AiProviderName(provider)].default_model
    return provider.value, model


def _add_run(
    session: AsyncSession,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    ctx: FrozenContext,
    *,
    run_id: uuid.UUID,
    task: AiTask,
    job_id: uuid.UUID | None,
    investigation_id: uuid.UUID | None,
    target_id: uuid.UUID | None,
    parent_run_id: uuid.UUID | None,
    supersedes_run_id: uuid.UUID | None,
    provider: str,
    model: str,
    deadline: datetime,
) -> AiRun:
    run = AiRun(
        id=run_id,
        organization_id=org_id,
        task=task.value,
        scope=AiScope.JOB.value if job_id is not None else AiScope.INVESTIGATION.value,
        job_id=job_id,
        investigation_id=investigation_id,
        target_kind=_TARGET_KINDS.get(task) if target_id is not None else None,
        target_id=target_id,
        parent_run_id=parent_run_id,
        provider=provider,
        model=model,
        prompt_version=PROMPT_VERSION,
        output_schema=OUTPUT_SCHEMA_VERSION,
        status=AiRunStatus.QUEUED.value,
        context_sha256=ctx.sha256,
        context_stats=ctx.stats.model_dump(mode="json"),
        requested_by=user_id,
        supersedes_run_id=supersedes_run_id,
        deadline_at=deadline,
    )
    session.add(run)
    return run


def _add_rows(
    session: AsyncSession,
    org_id: uuid.UUID,
    run_id: uuid.UUID,
    ctx: FrozenContext,
    *,
    deadline: datetime,
    now: datetime,
) -> None:
    session.add(
        AiRunIndex(
            run_id=run_id,
            organization_id=org_id,
            status=AiRunStatus.QUEUED.value,
            deadline_at=deadline,
            dispatched_at=now,
        )
    )
    session.add(
        AiRunInput(
            run_id=run_id,
            stage="base",
            organization_id=org_id,
            context=ctx.model_dump(mode="json", exclude={"pseudonym_map"}),
            context_sha256=ctx.sha256,
            pseudonym_map=dict(ctx.pseudonym_map),
        )
    )
    for ref in ctx.refs:
        session.add(
            AiContextRef(
                run_id=run_id,
                label=ref.label,
                organization_id=org_id,
                stage=ref.stage,
                kind=ref.kind.value,
                ref_table=ref.ref_table,
                ref_id=ref.ref_id,
                job_id=ref.job_id,
                fields_sha256=ref.fields_sha256,
            )
        )


def _audit_details(
    req: AiRunRequest,
    built: BuiltRun,
    provider: str,
    model: str,
    settings_row: Any,
    supersedes: uuid.UUID | None,
) -> dict[str, Any]:
    """Ids, enums and counts only: never a field value, title, filename or pseudonym."""
    stats = built.root.stats
    kinds: Counter[str] = Counter(item.kind.value for item in built.root.items)
    pseudonymized: Counter[str] = Counter(stats.pseudonymized)
    for child in built.children:
        kinds.update(item.kind.value for item in child.items)
        pseudonymized.update(child.stats.pseudonymized)
    return {
        "task": req.task.value,
        "scope": req.scope.value,
        "job_id": str(req.job_id) if req.job_id else None,
        "investigation_id": str(req.investigation_id) if req.investigation_id else None,
        "target_id": str(req.target_id) if req.target_id else None,
        "provider": provider,
        "model": model,
        "prompt_version": PROMPT_VERSION,
        "context_sha256": built.root.sha256,
        "children": len(built.children),
        "items": dict(sorted(kinds.items())),
        "pseudonymized": dict(sorted(pseudonymized.items())),
        "inclusions": {
            "pseudonymize_internal": bool(getattr(settings_row, "pseudonymize_internal", True)),
            "include_strings": bool(getattr(settings_row, "include_strings", False)),
            "include_ti": bool(getattr(settings_row, "include_ti", True)),
            "include_case_text": bool(getattr(settings_row, "include_case_text", False)),
        },
        "truncated": stats.truncated or any(c.stats.truncated for c in built.children),
        "omitted": stats.omitted + sum(c.stats.omitted for c in built.children),
        "jobs_omitted": stats.jobs_omitted,
        "regenerate": req.regenerate,
        "supersedes_run_id": str(supersedes) if supersedes else None,
    }


async def create_run_for_request(
    session: AsyncSession,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    req: AiRunRequest,
    built: BuiltRun,
    request: HTTPConnection | None = None,
) -> tuple[AiRun, bool]:
    """`create_run` with the HTTP request for the audit row's ip / user agent."""
    settings = get_settings()
    provider, model = _resolve(req)
    sha = built.root.sha256
    await repository.advisory_lock(session, org_lock_key(org_id))
    if not req.regenerate:
        existing = await _identical(session, org_id, req, provider, model, sha, DEDUPE_STATUSES)
        if existing is not None:
            return existing, True
    supersedes = None
    if req.regenerate:
        previous = await _identical(session, org_id, req, provider, model, sha, None)
        supersedes = previous.id if previous is not None else None

    needed = 1 + len(built.children)
    if await repository.count_active_runs(session, org_id) + needed > (
        settings.ai_active_runs_per_org
    ):
        raise AiBusy()
    await repository.advisory_lock(session, GLOBAL_RUNS_LOCK)
    if await _global_active() + needed > settings.ai_active_runs_global:
        raise AiBusy()

    now = datetime.now(UTC)
    seconds = (
        settings.ai_incident_deadline_s
        if req.task is AiTask.INCIDENT_SUMMARY
        else settings.ai_run_deadline_s
    )
    deadline = now + timedelta(seconds=seconds)
    root = _add_run(
        session,
        org_id,
        user_id,
        built.root,
        run_id=uuid.uuid4(),
        task=req.task,
        job_id=req.job_id,
        investigation_id=req.investigation_id,
        target_id=req.target_id,
        parent_run_id=None,
        supersedes_run_id=supersedes,
        provider=provider,
        model=model,
        deadline=deadline,
    )
    await session.flush()  # children reference the parent (composite self FK)
    children: list[tuple[uuid.UUID, FrozenContext]] = []
    for child in built.children:
        if len(child.scope.job_ids) != 1:
            raise ValueError("an incident child context covers exactly one job")
        child_id = uuid.uuid4()
        _add_run(
            session,
            org_id,
            user_id,
            child,
            run_id=child_id,
            task=AiTask.JOB_DIGEST,
            job_id=child.scope.job_ids[0],
            investigation_id=None,
            target_id=None,
            parent_run_id=root.id,
            supersedes_run_id=None,
            provider=provider,
            model=model,
            deadline=deadline,  # children inherit the parent's deadline (RT8)
        )
        children.append((child_id, child))
    await session.flush()
    _add_rows(session, org_id, root.id, built.root, deadline=deadline, now=now)
    for child_id, child in children:
        _add_rows(session, org_id, child_id, child, deadline=deadline, now=now)

    settings_row = await repository.org_settings(session, org_id)
    audit.record(
        session,
        action="ai.run_requested",
        org_id=org_id,
        actor_id=user_id,
        target_type="ai_run",
        target_id=root.id,
        details=_audit_details(req, built, provider, model, settings_row, supersedes),
        request=request,
    )
    await session.flush()
    await session.refresh(root)
    return root, False


async def create_run(
    session: AsyncSession,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    req: AiRunRequest,
    built: BuiltRun,
) -> tuple[AiRun, bool]:
    return await create_run_for_request(session, org_id, user_id, req, built)


def _send_sync(message: AiRunMessage) -> None:
    from app.workers.celery_app import celery_app  # broker client only, no worker

    celery_app.send_task(
        AI_RUN,
        kwargs={"message": message.model_dump(mode="json")},
        queue=Queues(get_settings().queue_prefix).analyst,
        retry=True,
        retry_policy={"max_retries": 1, "interval_start": 0, "interval_step": 0.5},
    )


async def _send(message: AiRunMessage) -> bool:
    try:
        with anyio.fail_after(SEND_TIMEOUT_S):
            await anyio.to_thread.run_sync(
                _send_sync, message, limiter=broker_limiter(), abandon_on_cancel=True
            )
    except Exception as exc:  # noqa: BLE001 - any broker failure is left to ai.resume
        log.warning("ai.run publish failed for run %s (%s)", message.run_id, type(exc).__name__)
        return False
    return True


async def dispatch(run_ids: Sequence[uuid.UUID]) -> None:
    """Publish `ai.run {run_id, org_id}` per run, in the given order (children first, then
    the parent), after the commit. The org comes from `ai_run_index` (system lookup); a
    lost publish is logged and left to `ai.resume` (the run keeps its `dispatched_at`)."""
    if not run_ids:
        return
    async with tenant_session(None, None) as session:
        rows = await session.execute(
            select(AiRunIndex.run_id, AiRunIndex.organization_id).where(
                AiRunIndex.run_id.in_(run_ids)
            )
        )
        orgs = {run_id: org_id for run_id, org_id in rows}
    for run_id in run_ids:
        org_id = orgs.get(run_id)
        if org_id is None:
            log.warning("ai.run not published: run %s has no index row", run_id)
            continue
        await _send(AiRunMessage(run_id=run_id, org_id=org_id))


__all__ = ["AiBusy", "create_run", "create_run_for_request", "dispatch"]
