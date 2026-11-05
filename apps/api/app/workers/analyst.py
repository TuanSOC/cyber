"""The trusted AI analyst worker (M5 phase 2): one message = at most one provider call (RT2).

`ai.run {run_id, org_id}`:
1. the run is looked up in the non-tenant `ai_run_index`; it must exist, belong to the
   message's org and be active, else the message is dropped (ids only);
2. the DB lease is taken (`lease_until = now() + 60 s` only if free or expired, and for a
   `waiting` run only once `resume_at` is due), else a duplicate exits; it is renewed every
   20 s, each renewal in its own short transaction;
3. short `tenant_session`s only (RT7): inputs are loaded, the run marked `running`, the
   budget reserved and `calls` bumped, each committed before the provider call; **no session
   is open during the call**; verification and persistence use new sessions afterwards;
4. per message: deadline (a child uses its parent's, RT8) and call cap; org and provider state
   re-read (`ai_disabled` / `provider_disabled` / `provider_unavailable`); an incident parent
   waits for its children, then reduces their verified digests (RT23); a `job_digest` reuses an
   identical completed digest without a call; the key (sealed org key, lazily re-sealed under
   the active kid (RT18); else the dev platform key with its global ceiling (RT17); else none
   for the mock); the prompt with a random delimiter and a URL-safe canary (only its sha256
   is kept);
   limiter, token budget (the day key seeded from the DB when missing, RT9), the call under
   `asyncio.timeout(AI_CALL_TIMEOUT_S)`;
5. typed outcomes (`ProviderError.kind`): waiting with `resume_at` (never past the deadline)
   or a final status; success settles the budget, verifies the output and writes
   `ai_outputs` + `ai_citations` + the run's usage / cost / metrics in one transaction. A
   child that ends wakes its parent.

`ai.resume` re-sends due runs; `ai.verify` checks one stored key. Logs carry run ids, task,
provider, model, outcome codes and token counts only: never context text, model output, keys
or provider error bodies.

Isolation (clone of the M4 enrich worker): `PROCESS_ROLE=analyst`, networks `enrich` +
`egress`, no JWT secret / MinIO / app Redis / TI private key (Settings refuses them), its own
broker user confined to `analyst*`. Only `app/workers/analyst*.py` may import `ai.unseal`.
"""

import asyncio
import base64
import contextlib
import hashlib
import logging
import secrets
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pydantic import SecretStr, ValidationError
from sqlalchemy import and_, func, or_, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.sealbox import SealedKey, raw_public
from app.core.tenancy import tenant_session
from app.modules.ai import lifecycle, prompt, verify
from app.modules.ai.availability import provider_available
from app.modules.ai.budget import (
    Budget,
    BudgetExhausted,
    BudgetUnavailable,
    Reservation,
    ceil_tokens,
)
from app.modules.ai.catalog import AI_CATALOG, PRICE_VERSION, cost_micros
from app.modules.ai.context import reduce
from app.modules.ai.contracts import (
    RUN_ACTIVE,
    RUN_FINAL,
    AiErrorCode,
    AiProviderName,
    AiRunStatus,
    AiTask,
    CitationResult,
    CitationStatus,
    ClaimStatus,
    ContextRef,
    DigestInput,
    FrozenContext,
    LlmProvider,
    OutputFlag,
    OutputVerification,
    PromptParts,
    ProviderError,
    ProviderErrorKind,
    ProviderRequest,
    ProviderResult,
    ProviderUsage,
    RunMetrics,
    RunScope,
    ValidationFailed,
    VerifiedOutput,
    VerifyOutcome,
    VerifyStatus,
)
from app.modules.ai.messages import AiResumeMessage, AiRunMessage, AiVerifyMessage
from app.modules.ai.models import (
    AiCitation,
    AiContextRef,
    AiOrgSettings,
    AiOutput,
    AiProviderConfig,
    AiRun,
    AiRunIndex,
    AiRunInput,
)
from app.modules.ai.output_schema import AnalysisOutput, provider_json_schema
from app.modules.ai.providers.registry import build_provider
from app.modules.ai.ratelimit import (
    AiLimiter,
    Decision,
    LimiterUnavailable,
    broker_redis,
    cooldown_seconds,
    effective_per_minute,
)
from app.modules.ai.seal import load_public_key, seal
from app.modules.ai.unseal import UnsealError, load_private_keys, open_sealed
from app.modules.audit import service as audit
from app.modules.investigations import policy as share_policy

log = logging.getLogger(__name__)

LEASE = timedelta(seconds=60)
LEASE_RENEW_S = 20.0
# A waiting run is due once `resume_at` is this close (clock skew between DB and beat).
RESUME_SLACK = timedelta(seconds=1)
PARENT_POLL_S = 30.0  # an incident parent re-checks its children
BROKER_RETRY_S = 30.0  # limiter / budget broker unreachable: fail closed, retry
TRANSIENT_RETRY_S = 10.0  # timeout / transport: one retry in the next message
OVERLOAD_BACKOFF_S = (30.0, 60.0, 120.0)  # 529: `attempts` on the index
COUNT_TOKENS_TIMEOUT_S = 30.0
# Budget seeding (RT8/RT9/RT17): `{where}` is always a fixed condition of this module.
_USED_SQL = (
    "SELECT coalesce(sum(coalesce((usage->>'input_tokens')::bigint, 0)"
    " + coalesce((usage->>'output_tokens')::bigint, 0)"
    " + coalesce((usage->>'cache_read_tokens')::bigint, 0)"
    " + coalesce((usage->>'cache_write_tokens')::bigint, 0)), 0)"
    " FROM ai_runs WHERE organization_id = :org AND ({where})"
)
_RUNNING_SQL = (
    "SELECT coalesce(sum(coalesce((context_stats->>'est_tokens')::bigint, 0) + :max_output), 0)"
    " FROM ai_runs WHERE organization_id = :org AND status = 'running' AND id <> :run"
    " AND ({where})"
)
PLATFORM_SEED_ORGS = 1000  # orgs scanned to re-seed the platform key after a broker restart
RESUME_BATCH = 100
REDISPATCH_AFTER = timedelta(minutes=2)
PUBLISH_TIMEOUT_S = 15.0
# An error that carries `usage` (phase 3: a refusal answered with a 200) is settled to it.
# Errors that carry no usage and are not billed: the reservation is released (settled to 0).
# A refusal is not billed by Anthropic (phase-3 seam), so it is released too. Any other
# error after the request was sent (timeout, transport, max_tokens, invalid output, 5xx)
# keeps the full reservation charged and marks `metrics.usage_unknown` (RT2); one that was
# never sent (`request_sent=False`) is always released.
NOT_BILLED = frozenset(
    {
        ProviderErrorKind.RATE_LIMITED,
        ProviderErrorKind.OVERLOADED,
        ProviderErrorKind.SPEND_LIMIT,
        ProviderErrorKind.AUTH_FAILED,
        ProviderErrorKind.CONTEXT_TOO_LARGE,
        ProviderErrorKind.BAD_REQUEST,
        ProviderErrorKind.REFUSED,
    }
)
# Answers that are retried after a wait and, when not billed, do not use up a call: the
# call cap (RT2) bounds billed calls; the deadline (and the overload backoff) bounds these.
UNBILLED_RETRY = frozenset({ProviderErrorKind.RATE_LIMITED, ProviderErrorKind.OVERLOADED})
GENERIC_SCHEMA_ERROR = "output: invalid_output"

Publish = Callable[[AiRunMessage], Awaitable[None]]


def check_startup(settings: Settings) -> None:
    """Refuse to start without a usable AI private key for the active kid (clear message)."""
    if settings.process_role != "analyst":
        raise RuntimeError("the analyst worker needs PROCESS_ROLE=analyst")
    path = settings.ai_seal_private_keys_file
    if path is None:
        raise RuntimeError("AI_SEAL_PRIVATE_KEYS_FILE is not set")
    try:
        keys = load_private_keys(path)
    except UnsealError as exc:
        raise RuntimeError(f"AI seal private key file {path} is unusable ({exc.code})") from None
    kid = settings.ai_seal_active_kid
    if not kid or kid not in keys:
        raise RuntimeError(f"AI seal private key file {path} lacks the active kid {kid!r}")
    published = settings.ai_seal_public_keys.get(kid)
    derived = base64.b64encode(raw_public(keys[kid].public_key())).decode()
    if published != derived:
        raise RuntimeError(f"AI_SEAL_PUBLIC_KEYS[{kid!r}] does not match the private key file")


# --- dependencies (injectable for tests) ---------------------------------------------------


async def _publish_celery(message: AiRunMessage) -> None:
    from cyberlab_jobs import AI_RUN

    from app.workers.analyst_app import celery_app, queues  # the worker's own broker user

    def send() -> None:
        celery_app.send_task(
            AI_RUN,
            kwargs={"message": message.model_dump(mode="json")},
            queue=queues.analyst,
            retry=True,
            retry_policy={"max_retries": 1, "interval_start": 0, "interval_step": 0.5},
        )

    async with asyncio.timeout(PUBLISH_TIMEOUT_S):
        await asyncio.to_thread(send)


@dataclass
class AnalystDeps:
    """Everything the worker calls across phases, injectable for tests (`tests/ai_doubles`)."""

    settings: Settings
    limiter: AiLimiter
    budget: Budget
    private_keys: Mapping[str, X25519PrivateKey]
    # `registry.build_provider(name, *, api_key, model, settings, org_options)`.
    build_provider: Callable[..., LlmProvider] = build_provider
    # `prompt.render(ctx, task, *, delimiter, canary)` / `prompt.repair_hint(errors)`.
    render: Callable[..., PromptParts] = prompt.render
    repair_hint: Callable[[list[str]], str] = prompt.repair_hint
    # `verify.verify_output(session, org_id, run_scope, ctx, refs, parsed, canary)`.
    verify_output: Callable[..., Awaitable[VerifiedOutput]] = verify.verify_output
    # `reduce.build_reduce_context(base, digests)`.
    build_reduce_context: Callable[[FrozenContext, list[DigestInput]], FrozenContext] = (
        reduce.build_reduce_context
    )
    publish: Publish = _publish_celery
    # The dev/test platform key (read once from AI_PLATFORM_KEY_FILE; never in prod).
    platform_key: SecretStr | None = None
    lease_renew_s: float = LEASE_RENEW_S


_deps: AnalystDeps | None = None


def _read_platform_key(settings: Settings) -> SecretStr | None:
    path = settings.ai_platform_key_file
    if path is None or settings.env == "prod":
        return None
    try:
        value = Path(path).read_text(encoding="utf-8").strip()
    except OSError as exc:
        log.warning("AI platform key file unreadable (%s)", type(exc).__name__)
        return None
    return SecretStr(value) if value else None


def get_deps() -> AnalystDeps:
    global _deps
    if _deps is None:
        settings = get_settings()
        if settings.ai_seal_private_keys_file is None:
            raise RuntimeError("AI_SEAL_PRIVATE_KEYS_FILE is not set")
        redis = broker_redis(settings.broker_url)
        _deps = AnalystDeps(
            settings=settings,
            limiter=AiLimiter(redis, settings.queue_prefix),
            budget=Budget(redis, settings.queue_prefix),
            private_keys=load_private_keys(settings.ai_seal_private_keys_file),
            platform_key=_read_platform_key(settings),
        )
    return _deps


# --- small helpers -------------------------------------------------------------------------


def _new_canary() -> str:
    """The per-call secret of the system prompt: 32 URL-safe characters (the prompt accepts
    16-128). Never stored or logged; only its sha256 goes into `metrics`."""
    return secrets.token_urlsafe(24)


def _drop(reason: str, message: Mapping[str, Any]) -> None:
    # Ids only: a message never carries anything else, but log nothing else either.
    log.warning("ai message dropped (%s): run %s", reason, str(message.get("run_id"))[:36])


def _add(a: ProviderUsage, b: ProviderUsage) -> ProviderUsage:
    return ProviderUsage(
        input_tokens=a.input_tokens + b.input_tokens,
        output_tokens=a.output_tokens + b.output_tokens,
        cache_read_tokens=a.cache_read_tokens + b.cache_read_tokens,
        cache_write_tokens=a.cache_write_tokens + b.cache_write_tokens,
    )


def _sealed(row: AiProviderConfig) -> SealedKey | None:
    if row.key_ct is None or not row.key_kid or row.key_epk is None or row.key_nonce is None:
        return None
    return SealedKey(
        kid=row.key_kid,
        key_version=row.key_version,
        epk=row.key_epk,
        nonce=row.key_nonce,
        ct=row.key_ct,
        last4=row.key_last4 or "",
    )


def _ref(row: AiContextRef) -> ContextRef:
    return ContextRef.model_validate(
        {
            "label": row.label,
            "kind": row.kind,
            "ref_table": row.ref_table,
            "ref_id": row.ref_id,
            "job_id": row.job_id,
            "fields_sha256": row.fields_sha256,
            "stage": row.stage,
        }
    )


async def _refs(session: AsyncSession, run_id: uuid.UUID) -> tuple[ContextRef, ...]:
    rows = (
        await session.scalars(
            select(AiContextRef).where(AiContextRef.run_id == run_id).order_by(AiContextRef.label)
        )
    ).all()
    return tuple(_ref(row) for row in rows)


async def _base_context(session: AsyncSession, run_id: uuid.UUID) -> FrozenContext | None:
    # Never selects `pseudonym_map` (RT26): the worker has no use for real internal names.
    raw = await session.scalar(
        select(AiRunInput.context).where(AiRunInput.run_id == run_id, AiRunInput.stage == "base")
    )
    if raw is None:
        return None
    try:
        return FrozenContext.model_validate(raw)
    except ValidationError:
        return None


@dataclass(frozen=True)
class _Config:
    """A snapshot of one provider config row (no plaintext ever)."""

    id: uuid.UUID
    provider: str
    enabled: bool
    sealed: SealedKey | None
    limits: dict[str, Any]


@dataclass
class _State:
    run_id: uuid.UUID
    task: AiTask
    provider: str
    model: str
    job_id: uuid.UUID | None
    parent_run_id: uuid.UUID | None
    context_sha256: str
    prompt_version: str
    expired: bool
    ctx: FrozenContext | None
    refs: tuple[ContextRef, ...]
    ai_enabled: bool
    daily_token_budget: int
    run_token_cap: int
    incident_token_cap: int
    config: _Config | None
    usage: ProviderUsage
    metrics: RunMetrics
    calls: int
    attempts: int
    # M6: the case of an investigation-scope run (the share-policy re-check).
    investigation_id: uuid.UUID | None = None


@dataclass
class _Call:
    """One provider call in flight (no secrets: the key lives in the adapter only)."""

    provider: LlmProvider
    ctx: FrozenContext
    refs: tuple[ContextRef, ...]
    canary: str
    estimate: int
    max_output: int
    reservation: Reservation
    partial: bool


class _KeyFailed(Exception):
    pass


class _Wait:
    """An incident parent whose children are not final yet."""


_WAIT = _Wait()


# --- one message ---------------------------------------------------------------------------


@dataclass
class _Work:
    deps: AnalystDeps
    org_id: uuid.UUID
    run_id: uuid.UUID
    token: str
    lease_lost: bool = False
    st: _State = field(init=False)

    @property
    def settings(self) -> Settings:
        return self.deps.settings

    # ---- lease

    async def renew_forever(self) -> None:
        while True:
            await asyncio.sleep(self.deps.lease_renew_s)
            try:
                async with tenant_session(None, None) as s:
                    renewed = await s.scalar(
                        update(AiRunIndex)
                        .where(
                            AiRunIndex.run_id == self.run_id, AiRunIndex.lease_owner == self.token
                        )
                        .values(lease_until=func.now() + LEASE)
                        .returning(AiRunIndex.run_id)
                    )
            except DBAPIError as exc:
                log.warning("ai run %s: lease renewal failed (%s)", self.run_id, type(exc).__name__)
                continue
            except Exception as exc:  # noqa: BLE001 - never kill the message; the lease expires
                log.warning(
                    "ai run %s: lease renewer stopped (%s)", self.run_id, type(exc).__name__
                )
                return
            if renewed is None:
                log.warning("ai run %s: lease lost", self.run_id)
                self.lease_lost = True
                return

    async def release(self) -> None:
        async with tenant_session(None, None) as s:
            await s.execute(
                update(AiRunIndex)
                .where(AiRunIndex.run_id == self.run_id, AiRunIndex.lease_owner == self.token)
                .values(lease_until=None, lease_owner=None)
            )

    # ---- load (one short transaction)

    async def _load(self) -> _State | None:
        async with tenant_session(self.org_id, None) as s:
            run = await s.scalar(
                select(AiRun)
                .where(AiRun.id == self.run_id, AiRun.organization_id == self.org_id)
                .with_for_update()
            )
            if run is None or run.status in RUN_FINAL:
                return None
            index = await s.get(AiRunIndex, self.run_id, with_for_update=True)
            if index is None:
                return None
            deadline = run.deadline_at
            if run.parent_run_id is not None:  # children inherit the parent's deadline (RT8)
                parent_deadline = await s.scalar(
                    select(AiRun.deadline_at).where(AiRun.id == run.parent_run_id)
                )
                if parent_deadline is not None:
                    deadline = min(deadline, parent_deadline)
            db_now: datetime = (await s.execute(select(func.now()))).scalar_one()
            org = await s.get(AiOrgSettings, self.org_id)
            config_row = await s.scalar(
                select(AiProviderConfig).where(
                    AiProviderConfig.organization_id == self.org_id,
                    AiProviderConfig.provider == run.provider,
                )
            )
            config = (
                _Config(
                    id=config_row.id,
                    provider=config_row.provider,
                    enabled=config_row.enabled,
                    sealed=_sealed(config_row),
                    limits=dict(config_row.limits or {}),
                )
                if config_row is not None
                else None
            )
            try:
                metrics = RunMetrics.model_validate(run.metrics or {})
            except ValidationError:
                metrics = RunMetrics()
            try:
                usage = ProviderUsage.model_validate(run.usage or {})
            except ValidationError:
                usage = ProviderUsage()
            ceilings = self.settings.ai_ceilings
            state = _State(
                run_id=run.id,
                task=AiTask(run.task),
                provider=run.provider,
                model=run.model,
                job_id=run.job_id,
                parent_run_id=run.parent_run_id,
                context_sha256=run.context_sha256,
                prompt_version=run.prompt_version,
                expired=db_now >= deadline,
                ctx=await _base_context(s, self.run_id),
                refs=await _refs(s, self.run_id),
                ai_enabled=bool(org and org.ai_enabled),
                daily_token_budget=min(
                    org.daily_token_budget if org else 0, ceilings.daily_token_budget
                ),
                run_token_cap=min(org.run_token_cap if org else 0, ceilings.run_token_cap),
                incident_token_cap=min(
                    org.incident_token_cap if org else 0, ceilings.incident_token_cap
                ),
                config=config,
                usage=usage,
                metrics=metrics,
                calls=index.calls,
                attempts=index.attempts,
                investigation_id=run.investigation_id,
            )
            if not state.expired:
                await lifecycle.mark_running(s, self.run_id)
        return state

    # ---- the steps

    async def run(self) -> AiRunStatus | None:
        state = await self._load()
        if state is None:
            return None
        self.st = state
        if state.expired:
            return await self._finish(AiRunStatus.FAILED, AiErrorCode.DEADLINE)
        if state.calls >= self.settings.ai_max_calls_per_run:
            return await self._finish(AiRunStatus.FAILED, AiErrorCode.PROVIDER_ERROR)
        if state.ctx is None:
            log.error("ai run %s: base input missing or unreadable", self.run_id)
            return await self._finish(AiRunStatus.FAILED, AiErrorCode.PROVIDER_ERROR)
        code = self._gate()
        if code is not None:
            return await self._finish(AiRunStatus.FAILED, code)

        ctx, refs, partial = state.ctx, state.refs, False
        if state.task is AiTask.INCIDENT_SUMMARY:
            reduced = await self._reduce(state.ctx)
            if isinstance(reduced, _Wait):
                return await self._wait(PARENT_POLL_S)
            if reduced is None:
                return await self._finish(AiRunStatus.FAILED, AiErrorCode.NO_DIGEST)
            if isinstance(reduced, AiErrorCode):
                return await self._finish(AiRunStatus.FAILED, reduced)
            ctx, refs, partial = reduced
        elif state.task is AiTask.JOB_DIGEST:
            reused = await self._reuse(state.ctx)
            if reused is not None:
                return reused

        try:
            key, platform = await self._key()
        except _KeyFailed:
            return await self._finish(AiRunStatus.FAILED, AiErrorCode.AUTH_FAILED)
        try:
            provider = self.deps.build_provider(
                state.provider,
                api_key=key,
                model=state.model,
                settings=self.settings,
                org_options={},
            )
        except Exception as exc:  # noqa: BLE001 - unknown provider / model, adapter missing
            log.warning("ai run %s: provider unavailable (%s)", self.run_id, type(exc).__name__)
            return await self._finish(AiRunStatus.FAILED, AiErrorCode.PROVIDER_UNAVAILABLE)
        del key
        try:
            return await self._call(provider, ctx, refs, platform=platform, partial=partial)
        finally:
            with contextlib.suppress(Exception):
                await provider.aclose()

    def _gate(self) -> AiErrorCode | None:
        st = self.st
        if not st.ai_enabled:
            return AiErrorCode.AI_DISABLED
        if st.config is None or not st.config.enabled:
            return AiErrorCode.PROVIDER_DISABLED
        available, reason = provider_available(self.settings, st.provider)
        if not available:
            if reason == "ai_disabled_platform":
                return AiErrorCode.AI_DISABLED
            return AiErrorCode.PROVIDER_UNAVAILABLE
        return None

    # ---- incident: map-reduce

    async def _reduce(
        self, base: FrozenContext
    ) -> tuple[FrozenContext, tuple[ContextRef, ...], bool] | AiErrorCode | _Wait | None:
        """`_WAIT` while children run; None when no child produced a digest; else the reduce
        context (stored once as `ai_run_inputs(stage=reduce)`), its refs and `partial`."""
        async with tenant_session(self.org_id, None) as s:
            children = (
                await s.execute(
                    select(AiRun.id, AiRun.status, AiRun.job_id)
                    .where(
                        AiRun.organization_id == self.org_id,
                        AiRun.parent_run_id == self.run_id,
                    )
                    .order_by(AiRun.created_at, AiRun.id)
                )
            ).all()
            if any(child.status not in RUN_FINAL for child in children):
                return _WAIT
            done = [c for c in children if c.status == AiRunStatus.COMPLETED]
            stored = await s.scalar(
                select(AiRunInput.context).where(
                    AiRunInput.run_id == self.run_id, AiRunInput.stage == "reduce"
                )
            )
            if stored is not None:  # redelivery: the reduce context is frozen already
                if not done:
                    return None
                try:
                    ctx = FrozenContext.model_validate(stored)
                except ValidationError:
                    return AiErrorCode.PROVIDER_ERROR
                return ctx, await _refs(s, self.run_id), len(done) < len(children)
            numbers = {job: n for n, job in enumerate(base.scope.job_ids, start=1)}
            digests: list[DigestInput] = []
            for child in done:
                number = numbers.get(child.job_id) if child.job_id is not None else None
                if number is None:
                    number = len(numbers) + 1
                    numbers[child.job_id] = number
                digest = await self._digest(s, child.id, child.job_id, number)
                if digest is not None:
                    digests.append(digest)
        if not digests:
            return None
        try:
            ctx = self.deps.build_reduce_context(base, digests)
        except Exception as exc:  # noqa: BLE001 - a builder bug or refusal: never a call
            log.error("ai run %s: reduce context failed (%s)", self.run_id, type(exc).__name__)
            return AiErrorCode.PROVIDER_ERROR
        async with tenant_session(self.org_id, None) as s:
            await s.execute(
                pg_insert(AiRunInput)
                .values(
                    run_id=self.run_id,
                    stage="reduce",
                    organization_id=self.org_id,
                    context=ctx.model_dump(mode="json", exclude={"pseudonym_map"}),
                    context_sha256=ctx.sha256,
                    pseudonym_map={},
                )
                .on_conflict_do_nothing(index_elements=["run_id", "stage"])
            )
            if ctx.refs:
                await s.execute(
                    pg_insert(AiContextRef)
                    .values(
                        [
                            {
                                "run_id": self.run_id,
                                "label": ref.label,
                                "organization_id": self.org_id,
                                "stage": ref.stage,
                                "kind": ref.kind.value,
                                "ref_table": ref.ref_table,
                                "ref_id": ref.ref_id,
                                "job_id": ref.job_id,
                                "fields_sha256": ref.fields_sha256,
                            }
                            for ref in ctx.refs
                        ]
                    )
                    .on_conflict_do_nothing(index_elements=["run_id", "label"])
                )
            refs = await _refs(s, self.run_id)
        return ctx, refs, len(digests) < len(children)

    async def _digest(
        self, s: AsyncSession, child_id: uuid.UUID, job_id: uuid.UUID | None, number: int
    ) -> DigestInput | None:
        """A completed child's verified output as a reduce input: supported claims and
        hypotheses only, their verified citations, the child's flags (RT23). A child whose
        output leaked the canary contributes nothing."""
        if job_id is None:
            return None
        row = (
            await s.execute(
                select(AiOutput.body, AiOutput.verification, AiOutput.flags).where(
                    AiOutput.run_id == child_id, AiOutput.organization_id == self.org_id
                )
            )
        ).first()
        context = await _base_context(s, child_id)
        if row is None or context is None:
            return None
        known = {f.value for f in OutputFlag}
        flags = tuple(OutputFlag(f) for f in row.flags or [] if f in known)
        if OutputFlag.CANARY_LEAK in flags:
            return None
        try:
            body = AnalysisOutput.model_validate(row.body)
            verification = OutputVerification.model_validate(row.verification or {})
        except ValidationError:
            return None
        claims = verification.claims
        supported = {
            cid for cid, verdict in claims.items() if verdict.status is ClaimStatus.SUPPORTED
        }
        hypotheses = {h.id for h in body.hypotheses}
        body = body.model_copy(
            update={
                "observed": [c for c in body.observed if c.id in supported],
                "interpretation": [c for c in body.interpretation if c.id in supported],
            }
        )
        kept = {c.id for c in body.observed} | {c.id for c in body.interpretation} | hypotheses
        rows = (
            await s.scalars(
                select(AiCitation)
                .where(
                    AiCitation.run_id == child_id,
                    AiCitation.organization_id == self.org_id,
                    AiCitation.status == CitationStatus.VERIFIED,
                )
                .order_by(AiCitation.claim_path)
            )
        ).all()
        citations = tuple(
            CitationResult.model_validate(
                {
                    "claim_path": c.claim_path,
                    "section": c.section,
                    "claim_id": c.claim_id,
                    "label": c.label,
                    "kind": c.kind,
                    "ref_id": c.ref_id,
                    "job_id": c.job_id,
                    "field": c.field,
                    "quote": c.quote,
                    "status": c.status,
                    "reason": c.reason,
                    "stale": c.stale,
                }
            )
            for c in rows
            if c.claim_id in kept
        )
        return DigestInput(
            run_id=child_id,
            job_id=job_id,
            job_label=f"J{number}",
            context=context,
            body=body,
            claims={cid: v for cid, v in claims.items() if cid in kept},
            citations=citations,
            flags=flags,
        )

    # ---- job_digest reuse

    async def _reuse(self, ctx: FrozenContext) -> AiRunStatus | None:
        """Copy an identical completed digest (org, job, context_sha256, model,
        prompt_version) into this run without a call; its citations are re-verified."""
        st = self.st
        async with tenant_session(self.org_id, None) as s:
            source = (
                await s.execute(
                    select(AiRun.id, AiRun.served_model, AiOutput.body)
                    .join(
                        AiOutput,
                        and_(
                            AiOutput.run_id == AiRun.id,
                            AiOutput.organization_id == AiRun.organization_id,
                        ),
                    )
                    .where(
                        AiRun.organization_id == self.org_id,
                        AiRun.task == AiTask.JOB_DIGEST,
                        AiRun.job_id == st.job_id,
                        AiRun.context_sha256 == st.context_sha256,
                        AiRun.model == st.model,
                        AiRun.prompt_version == st.prompt_version,
                        AiRun.status == AiRunStatus.COMPLETED,
                        AiRun.id != self.run_id,
                    )
                    .order_by(AiRun.finished_at.desc().nulls_last(), AiRun.id)
                    .limit(1)
                )
            ).first()
            if source is None:
                return None
            try:
                verified = await self.deps.verify_output(
                    s, self.org_id, ctx.scope, ctx, st.refs, dict(source.body), _new_canary()
                )
            except Exception as exc:  # noqa: BLE001 - not reusable: make the call instead
                log.warning("ai run %s: digest not reusable (%s)", self.run_id, type(exc).__name__)
                return None
        if OutputFlag.CANARY_LEAK in verified.flags:
            return None
        verification = verified.verification.model_copy(update={"reused_from_run_id": source.id})
        verified = verified.model_copy(update={"verification": verification})
        values = {
            "usage": ProviderUsage().model_dump(),
            "cost_micros": 0,
            "price_version": PRICE_VERSION,
            "served_model": source.served_model,
            "metrics": verified.metrics.model_dump(mode="json"),
        }
        status = await self._persist(verified, AiRunStatus.COMPLETED, None, values)
        if status is not None:
            log.info("ai run %s %s: digest reused from %s", self.run_id, st.task, source.id)
        return status

    # ---- key

    async def _key(self) -> tuple[SecretStr | None, bool]:
        """(key, is_platform_key). Raises `_KeyFailed` (-> `auth_failed`, verify_status
        untouched)."""
        st = self.st
        config = st.config
        if config is not None and config.sealed is not None:
            try:
                key = open_sealed(
                    config.sealed, self.org_id, config.provider, self.deps.private_keys
                )
            except UnsealError as exc:
                log.warning("ai run %s: key unseal failed (%s)", self.run_id, exc.code)
                raise _KeyFailed from None
            await self._maybe_reseal(config, key)
            return key, False
        settings = self.settings
        if (
            settings.env != "prod"
            and settings.ai_platform_key_file is not None
            and settings.ai_platform_provider is not None
            and settings.ai_platform_provider.value == st.provider
        ):
            if self.deps.platform_key is None:
                raise _KeyFailed
            return self.deps.platform_key, True
        if st.provider == AiProviderName.MOCK:
            return None, False
        raise _KeyFailed

    async def _maybe_reseal(self, config: _Config, key: SecretStr) -> None:
        """Re-seal a key opened under an old kid with the active one (same `key_version`,
        RT18); a clone of `enrich._maybe_reseal`."""
        sealed = config.sealed
        active = self.settings.ai_seal_active_kid
        if sealed is None or not active or sealed.kid == active:
            return
        encoded = self.settings.ai_seal_public_keys.get(active)
        if encoded is None:
            return
        try:
            fresh = seal(
                key,
                self.org_id,
                config.provider,
                active,
                sealed.key_version,
                load_public_key(encoded),
            )
            async with tenant_session(self.org_id, None) as s:
                await s.execute(
                    update(AiProviderConfig)
                    .where(
                        AiProviderConfig.id == config.id,
                        AiProviderConfig.key_kid == sealed.kid,
                        AiProviderConfig.key_version == sealed.key_version,
                    )
                    .values(
                        key_kid=fresh.kid,
                        key_epk=fresh.epk,
                        key_nonce=fresh.nonce,
                        key_ct=fresh.ct,
                        key_last4=fresh.last4,
                    )
                )
            log.info("ai key re-sealed under kid %s (%s)", active, config.provider)
        except Exception as exc:  # noqa: BLE001 - a failed re-seal never blocks the call
            log.warning("ai key re-seal failed (%s): %s", config.provider, type(exc).__name__)

    # ---- budget helpers

    async def _tokens(self, org_id: uuid.UUID, where: str, params: Mapping[str, Any]) -> int:
        """Usage of the org's runs matching `where` (a fixed condition of this module, never
        input), plus the reservation estimate of those still running (this run excluded:
        its own reservation is being made)."""
        values = {
            **params,
            "org": org_id,
            "run": self.run_id,
            "max_output": self.settings.ai_max_output_tokens,
        }
        async with tenant_session(org_id, None) as s:
            used = await s.scalar(text(_USED_SQL.format(where=where)), values)
            running = await s.scalar(text(_RUNNING_SQL.format(where=where)), values)
        return int(used or 0) + int(running or 0)

    @staticmethod
    def _midnight() -> datetime:
        return datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)

    async def _seed_day(self) -> int:
        """Today's tokens of the org from the DB (RT9): runs created or finished today."""
        return await self._tokens(
            self.org_id,
            "created_at >= :midnight OR finished_at >= :midnight",
            {"midnight": self._midnight()},
        )

    async def _seed_tree(self) -> int:
        """An incident tree's tokens from the DB (RT8): the root and its children."""
        tree = self._tree()
        if tree is None:
            return 0
        return await self._tokens(
            self.org_id, "id = :root OR parent_run_id = :root", {"root": tree[0]}
        )

    async def _seed_platform(self) -> int:
        """The dev platform key's tokens today, from the DB (RT17): the runs of its provider
        in every org with runs today that has no sealed key of its own for that provider (an
        approximation: an org that stored its own key since then is not counted). Orgs come
        from the non-tenant `ai_run_index` (system data)."""
        provider = self.settings.ai_platform_provider
        if provider is None:
            return 0
        name = AiProviderName(provider).value
        midnight = self._midnight()
        async with tenant_session(None, None) as s:
            orgs = (
                await s.scalars(
                    select(AiRunIndex.organization_id)
                    .where(AiRunIndex.deadline_at >= midnight)
                    .distinct()
                    .limit(PLATFORM_SEED_ORGS)
                )
            ).all()
        total = 0
        for org_id in orgs:
            async with tenant_session(org_id, None) as s:
                own_key = await s.scalar(
                    select(AiProviderConfig.key_ct).where(
                        AiProviderConfig.organization_id == org_id,
                        AiProviderConfig.provider == name,
                    )
                )
            if own_key is not None:
                continue
            total += await self._tokens(
                org_id,
                "provider = :provider AND (created_at >= :midnight OR finished_at >= :midnight)",
                {"provider": name, "midnight": midnight},
            )
        return total

    def _tree(self) -> tuple[uuid.UUID, int] | None:
        st = self.st
        if st.task is AiTask.INCIDENT_SUMMARY:
            return self.run_id, st.incident_token_cap
        if st.task is AiTask.JOB_DIGEST and st.parent_run_id is not None:
            return st.parent_run_id, st.incident_token_cap
        return None

    async def _settle(self, reservation: Reservation, actual: int) -> None:
        try:
            await self.deps.budget.settle(reservation, actual)
        except BudgetUnavailable:
            log.warning("ai run %s: budget settle failed (broker)", self.run_id)

    async def _estimate(
        self, provider: LlmProvider, request: ProviderRequest, ctx: FrozenContext
    ) -> int:
        """Anthropic: the provider's `count_tokens`; otherwise the context estimator (never
        below chars/4 of what is sent)."""
        fallback = max(ctx.stats.est_tokens, ceil_tokens(len(request.system) + len(request.user)))
        if self.st.provider == AiProviderName.ANTHROPIC:
            try:
                async with asyncio.timeout(COUNT_TOKENS_TIMEOUT_S):
                    counted = await provider.count_tokens(request)
            except Exception as exc:  # noqa: BLE001 - the estimate is the fallback
                log.info("ai run %s: count_tokens failed (%s)", self.run_id, type(exc).__name__)
                counted = None
            if counted is not None and counted > 0:
                return counted
        return fallback

    async def _policy_blocked(self, scope: RunScope) -> bool:
        """M6 (RT20): the case / evidence share policy as it is now (one short transaction).
        A job-scope run (a `job_digest` child too) checks its job's evidence and case. An
        investigation-scope run checks its case **and** the run's frozen scope: the jobs and
        evidence whose rows are in the context, so an evidence exclusion added after the
        request blocks it too. A flag set after the request fails the run `policy_blocked`
        without a provider call; a call already in flight completes (the documented
        residual)."""
        st = self.st
        async with tenant_session(self.org_id, None) as s:
            if st.job_id is not None:
                found = await share_policy.load_policy(s, self.org_id, job_ids=(st.job_id,))
            elif st.investigation_id is not None:
                found = await share_policy.load_policy(
                    s,
                    self.org_id,
                    investigation_id=st.investigation_id,
                    job_ids=scope.job_ids,
                    evidence_ids=scope.evidence_ids,
                )
            else:
                return False
        blocked = found.ai_blocked or not found.excluded_evidence_ids.isdisjoint(scope.evidence_ids)
        if blocked:
            reason = found.ai_reason or share_policy.EVIDENCE_AI_EXCLUDED
            log.info("ai run %s: blocked by the share policy (%s)", self.run_id, reason)
        return blocked

    async def _refund_call(self) -> int | None:
        """Undo `_count_call` for an unbilled rate-limit / overload answer. None when the
        lease was lost."""
        async with tenant_session(self.org_id, None) as s:
            calls: int | None = await s.scalar(
                update(AiRunIndex)
                .where(AiRunIndex.run_id == self.run_id, AiRunIndex.lease_owner == self.token)
                .values(calls=func.greatest(AiRunIndex.calls - 1, 0))
                .returning(AiRunIndex.calls)
            )
        return calls

    async def _count_call(self) -> int | None:
        """Bump `calls` and commit before the call (RT2). None when the lease was lost."""
        async with tenant_session(self.org_id, None) as s:
            calls: int | None = await s.scalar(
                update(AiRunIndex)
                .where(AiRunIndex.run_id == self.run_id, AiRunIndex.lease_owner == self.token)
                .values(calls=AiRunIndex.calls + 1)
                .returning(AiRunIndex.calls)
            )
        return calls

    # ---- the call

    async def _call(
        self,
        provider: LlmProvider,
        ctx: FrozenContext,
        refs: tuple[ContextRef, ...],
        *,
        platform: bool,
        partial: bool,
    ) -> AiRunStatus | None:
        st = self.st
        settings = self.settings
        canary = _new_canary()
        try:
            parts = self.deps.render(ctx, st.task, delimiter=secrets.token_hex(16), canary=canary)
        except Exception as exc:  # noqa: BLE001 - a template bug: never a call
            log.error("ai run %s: prompt render failed (%s)", self.run_id, type(exc).__name__)
            return await self._finish(AiRunStatus.FAILED, AiErrorCode.PROVIDER_ERROR)
        user = parts.user
        if st.metrics.repaired:  # this call is the one schema-repair retry
            try:
                errors = await self.deps.limiter.load_repair(self.run_id)
            except LimiterUnavailable:
                errors = []
            try:
                user = f"{user}\n\n{self.deps.repair_hint(errors or [GENERIC_SCHEMA_ERROR])}"
            except Exception as exc:  # noqa: BLE001 - the plain prompt still works
                log.warning("ai run %s: repair hint failed (%s)", self.run_id, type(exc).__name__)
        max_output = settings.ai_max_output_tokens
        request = ProviderRequest(
            model=st.model,
            system=parts.system,
            user=user,
            output_schema=provider_json_schema(st.provider),
            max_output_tokens=max_output,
            effort=settings.ai_anthropic_effort
            if st.provider == AiProviderName.ANTHROPIC
            else None,
            context=ctx,
        )
        # M6 (RT20): the share policy is re-checked before every provider request,
        # `count_tokens` included (it sends the content too).
        if await self._policy_blocked(ctx.scope):
            return await self._finish(AiRunStatus.FAILED, AiErrorCode.POLICY_BLOCKED)
        estimate = await self._estimate(provider, request, ctx)
        if estimate + max_output > st.run_token_cap:
            return await self._finish(AiRunStatus.FAILED, AiErrorCode.CONTEXT_TOO_LARGE)

        per_minute = effective_per_minute(
            settings, st.provider, st.config.limits if st.config else None
        )
        try:
            acquired = await self.deps.limiter.acquire(st.provider, self.org_id, per_minute)
        except LimiterUnavailable:
            log.warning("ai run %s: limiter unavailable; waiting", self.run_id)
            return await self._wait(BROKER_RETRY_S)
        if acquired.decision is not Decision.OK:
            return await self._wait(max(1.0, acquired.wait_s))
        try:
            reservation = await self.deps.budget.reserve(
                self.org_id,
                estimate + max_output,
                daily_limit=st.daily_token_budget,
                seed=self._seed_day,
                tree=self._tree(),
                seed_tree=self._seed_tree,
                platform_limit=settings.ai_platform_daily_tokens if platform else None,
                seed_platform=self._seed_platform,
            )
        except BudgetExhausted as exc:
            log.info("ai run %s: %s budget exhausted", self.run_id, exc.scope)
            return await self._finish(AiRunStatus.FAILED, AiErrorCode.BUDGET_EXHAUSTED)
        except BudgetUnavailable:
            log.warning("ai run %s: budget unavailable; waiting", self.run_id)
            return await self._wait(BROKER_RETRY_S)

        if self.st.provider == AiProviderName.ANTHROPIC and await self._policy_blocked(ctx.scope):
            # count_tokens took a round trip: check once more right before the call.
            await self._settle(reservation, 0)
            return await self._finish(AiRunStatus.FAILED, AiErrorCode.POLICY_BLOCKED)
        calls = await self._count_call()
        if calls is None:
            await self._settle(reservation, 0)
            log.warning("ai run %s: lease lost before the call", self.run_id)
            return None
        st.calls = calls
        call = _Call(provider, ctx, refs, canary, estimate, max_output, reservation, partial)
        # No session is open from here until the call returns (RT7).
        try:
            async with asyncio.timeout(settings.ai_call_timeout_s):
                result = await provider.analyze(request)
        except TimeoutError:
            return await self._on_error(
                ProviderError(ProviderErrorKind.TIMEOUT, request_sent=True), call
            )
        except ProviderError as exc:
            return await self._on_error(exc, call)
        except Exception as exc:  # noqa: BLE001 - an adapter bug: typed, assumed sent
            log.warning("ai run %s: provider raised %s", self.run_id, type(exc).__name__)
            return await self._on_error(
                ProviderError(ProviderErrorKind.PROVIDER_ERROR, request_sent=True), call
            )
        return await self._on_result(result, call)

    def _values(self, usage: ProviderUsage, metrics: RunMetrics) -> dict[str, Any]:
        return {"usage": usage.model_dump(), "metrics": metrics.model_dump(mode="json")}

    async def _on_error(self, err: ProviderError, call: _Call) -> AiRunStatus | None:
        st = self.st
        usage, metrics = st.usage, st.metrics
        reported = getattr(err, "usage", None)  # e.g. a refusal answered with a 200 (phase 3)
        if isinstance(reported, ProviderUsage):
            # The provider said what it billed: settle to exactly that.
            await self._settle(call.reservation, reported.total)
            usage = _add(usage, reported)
        elif err.request_sent and err.kind not in NOT_BILLED:
            # Assumed billed (RT2): the reservation stays charged and the run's usage counts
            # it, flagged as unknown.
            usage = _add(
                usage, ProviderUsage(input_tokens=call.estimate, output_tokens=call.max_output)
            )
            metrics = metrics.model_copy(update={"usage_unknown": True})
        else:
            await self._settle(call.reservation, 0)
            if err.kind in UNBILLED_RETRY:
                # A 429/529 the provider did not bill is not a call (RT2 caps billed calls):
                # give it back, so a rate limit hit with the cap used still parks the run
                # until the cooldown (bounded by the deadline) instead of failing it.
                refunded = await self._refund_call()
                if refunded is not None:
                    st.calls = refunded
        values = self._values(usage, metrics)
        calls_left = st.calls < self.settings.ai_max_calls_per_run
        kind = err.kind
        log.info(
            "ai run %s %s: %s/%s %s (call %d)",
            self.run_id,
            st.task,
            st.provider,
            st.model,
            kind.value,
            st.calls,
        )
        limiter = self.deps.limiter
        if kind is ProviderErrorKind.RATE_LIMITED:
            seconds = cooldown_seconds(err.retry_after_s, limiter.now())
            with contextlib.suppress(LimiterUnavailable):
                await limiter.set_cooldown(st.provider, self.org_id, seconds)
            if calls_left:
                return await self._wait(seconds, values=values)
            return await self._finish(AiRunStatus.FAILED, AiErrorCode.PROVIDER_ERROR, values)
        if kind is ProviderErrorKind.OVERLOADED:
            if calls_left and st.attempts < len(OVERLOAD_BACKOFF_S):
                return await self._wait(
                    OVERLOAD_BACKOFF_S[st.attempts], values=values, attempts=st.attempts + 1
                )
            return await self._finish(AiRunStatus.FAILED, AiErrorCode.OVERLOADED, values)
        if kind is ProviderErrorKind.SPEND_LIMIT:
            with contextlib.suppress(LimiterUnavailable):
                await limiter.cooldown_until_midnight(st.provider, self.org_id)
            return await self._finish(AiRunStatus.FAILED, AiErrorCode.SPEND_LIMIT, values)
        if kind is ProviderErrorKind.AUTH_FAILED:
            verdict = await _verify_provider(call.provider)
            if verdict.status is VerifyStatus.VALID:
                return await self._finish(AiRunStatus.FAILED, AiErrorCode.PROVIDER_ERROR, values)
            if verdict.status is VerifyStatus.INVALID and st.config and st.config.sealed:
                await _save_verify(
                    self.org_id, st.config.id, st.config.sealed.key_version, verdict, inline=True
                )
            return await self._finish(AiRunStatus.FAILED, AiErrorCode.AUTH_FAILED, values)
        if kind is ProviderErrorKind.REFUSED:
            metrics = metrics.model_copy(update={"refusal_category": err.category})
            return await self._finish(
                AiRunStatus.REFUSED, AiErrorCode.REFUSED, self._values(usage, metrics)
            )
        if kind is ProviderErrorKind.MAX_TOKENS:
            return await self._finish(AiRunStatus.FAILED, AiErrorCode.MAX_TOKENS, values)
        if kind is ProviderErrorKind.INVALID_OUTPUT:
            return await self._repair_or_fail([GENERIC_SCHEMA_ERROR], usage, metrics)
        if kind is ProviderErrorKind.CONTEXT_TOO_LARGE:
            return await self._finish(AiRunStatus.FAILED, AiErrorCode.CONTEXT_TOO_LARGE, values)
        if kind in (ProviderErrorKind.TIMEOUT, ProviderErrorKind.TRANSPORT) and calls_left:
            return await self._wait(TRANSIENT_RETRY_S, values=values)
        return await self._finish(AiRunStatus.FAILED, AiErrorCode.PROVIDER_ERROR, values)

    async def _repair_or_fail(
        self, errors: list[str], usage: ProviderUsage, metrics: RunMetrics
    ) -> AiRunStatus | None:
        """The one schema-repair retry (budgeted like any call), in the next message."""
        st = self.st
        if not st.metrics.repaired and st.calls < self.settings.ai_max_calls_per_run:
            with contextlib.suppress(LimiterUnavailable):
                await self.deps.limiter.save_repair(self.run_id, errors)
            metrics = metrics.model_copy(update={"repaired": True})
            return await self._wait(0.0, values=self._values(usage, metrics), republish=True)
        return await self._finish(
            AiRunStatus.FAILED, AiErrorCode.INVALID_OUTPUT, self._values(usage, metrics)
        )

    def _cost(self, served_model: str, usage: ProviderUsage) -> tuple[int | None, bool]:
        cost = cost_micros(served_model, usage)
        if cost is not None:
            return cost, False
        return cost_micros(self.st.model, usage), True

    async def _on_result(self, result: ProviderResult, call: _Call) -> AiRunStatus | None:
        st = self.st
        await self._settle(call.reservation, result.usage.total)
        usage = _add(st.usage, result.usage)
        cost, estimated = self._cost(result.served_model, usage)
        metrics = st.metrics.model_copy(
            update={
                "cost_estimated": estimated,
                "canary_sha256": hashlib.sha256(call.canary.encode()).hexdigest(),
            }
        )
        values: dict[str, Any] = {
            **self._values(usage, metrics),
            "served_model": result.served_model[:64],
            "cost_micros": cost,
            "price_version": PRICE_VERSION,
        }
        if result.stop_reason == "refusal":
            metrics = metrics.model_copy(update={"refusal_category": result.refusal_category})
            values["metrics"] = metrics.model_dump(mode="json")
            return await self._finish(AiRunStatus.REFUSED, AiErrorCode.REFUSED, values)
        if result.stop_reason == "max_tokens":
            return await self._finish(AiRunStatus.FAILED, AiErrorCode.MAX_TOKENS, values)
        try:
            async with tenant_session(self.org_id, None) as s:
                verified = await self.deps.verify_output(
                    s,
                    self.org_id,
                    call.ctx.scope,
                    call.ctx,
                    call.refs,
                    dict(result.parsed),
                    call.canary,
                )
        except ValidationFailed as exc:
            return await self._repair_or_fail(exc.errors, usage, metrics)
        except Exception as exc:  # noqa: BLE001 - never re-bill a call for a verifier bug
            log.error("ai run %s: verification failed (%s)", self.run_id, type(exc).__name__)
            return await self._finish(AiRunStatus.FAILED, AiErrorCode.PROVIDER_ERROR, values)
        final = verified.metrics.model_copy(
            update={
                "usage_unknown": st.metrics.usage_unknown,
                "cost_estimated": estimated,
                "canary_sha256": metrics.canary_sha256,
                "repaired": st.metrics.repaired,
                "refusal_category": None,
            }
        )
        values["metrics"] = final.model_dump(mode="json")
        flags = set(verified.flags) | set(verified.metrics.flags)
        if OutputFlag.CANARY_LEAK in flags:
            # Persisted with the flag for review; the API never returns it as content.
            return await self._persist(
                verified, AiRunStatus.FAILED, AiErrorCode.CANARY_LEAK, values
            )
        status = AiRunStatus.PARTIAL if call.partial else AiRunStatus.COMPLETED
        return await self._persist(verified, status, None, values)

    # ---- endings

    async def _persist(
        self,
        verified: VerifiedOutput,
        status: AiRunStatus,
        code: AiErrorCode | None,
        values: Mapping[str, Any],
    ) -> AiRunStatus | None:
        """One transaction: `ai_outputs` + `ai_citations` + the run row, then the index."""
        async with tenant_session(self.org_id, None) as s:
            current = await s.scalar(
                select(AiRun.status).where(AiRun.id == self.run_id).with_for_update()
            )
            owner = await s.scalar(
                select(AiRunIndex.lease_owner)
                .where(AiRunIndex.run_id == self.run_id)
                .with_for_update()
            )
            if current is None or current in RUN_FINAL or owner != self.token:
                log.warning("ai run %s: lease lost; output discarded", self.run_id)
                return None
            output = AiOutput(
                organization_id=self.org_id,
                run_id=self.run_id,
                body=verified.body.model_dump(mode="json"),
                verification=verified.verification.model_dump(mode="json"),
                flags=[f.value for f in verified.flags],
            )
            s.add(output)
            await s.flush()
            claims = verified.verification.claims
            for c in verified.citations:
                verdict = claims.get(c.claim_id) if c.claim_id else None
                s.add(
                    AiCitation(
                        organization_id=self.org_id,
                        output_id=output.id,
                        run_id=self.run_id,
                        claim_path=c.claim_path,
                        section=c.section,
                        claim_id=c.claim_id,
                        claim_status=(
                            verdict.status.value
                            if verdict is not None and c.section != "next_steps"
                            else None
                        ),
                        label=c.label,
                        kind=c.kind.value if c.kind else None,
                        ref_id=c.ref_id,
                        job_id=c.job_id,
                        status=c.status.value,
                        reason=c.reason.value if c.reason else None,
                        field=c.field,
                        quote=c.quote,
                        stale=c.stale,
                    )
                )
            await s.flush()
            final = await lifecycle.finalize(
                s, self.run_id, status, code, values=values, lease_owner=self.token
            )
        if final is not None:
            self._log_final(final, code, values)
            await self._wake_parent()
        return final

    async def _finish(
        self,
        status: AiRunStatus,
        code: AiErrorCode | None,
        values: Mapping[str, Any] | None = None,
    ) -> AiRunStatus | None:
        async with tenant_session(self.org_id, None) as s:
            final = await lifecycle.finalize(
                s, self.run_id, status, code, values=values, lease_owner=self.token
            )
        if final is not None:
            self._log_final(final, code, values or {})
            await self._wake_parent()
        return final

    def _log_final(
        self, status: AiRunStatus, code: AiErrorCode | None, values: Mapping[str, Any]
    ) -> None:
        st = getattr(self, "st", None)
        usage = values.get("usage") or {}
        log.info(
            "ai run %s %s: %s/%s %s%s in=%s out=%s calls=%s",
            self.run_id,
            st.task.value if st else "-",
            st.provider if st else "-",
            st.model if st else "-",
            status.value,
            f"/{code.value}" if code else "",
            usage.get("input_tokens", 0),
            usage.get("output_tokens", 0),
            st.calls if st else "-",
        )

    async def _wait(
        self,
        seconds: float,
        *,
        values: Mapping[str, Any] | None = None,
        attempts: int | None = None,
        republish: bool = False,
    ) -> AiRunStatus | None:
        """running -> waiting (`resume_at` never past the deadline). `republish` sends the
        next message now (the repair retry) instead of waiting for `ai.resume`."""
        async with tenant_session(self.org_id, None) as s:
            resume_at = await lifecycle.set_waiting(
                s,
                self.run_id,
                resume_in_s=seconds,
                values=values,
                attempts=attempts,
                lease_owner=self.token,
            )
            if resume_at is not None and republish:
                await s.execute(
                    update(AiRunIndex)
                    .where(AiRunIndex.run_id == self.run_id)
                    .values(dispatched_at=func.now())
                )
        if resume_at is None:
            return None
        log.info("ai run %s waiting until %s", self.run_id, resume_at.isoformat())
        if republish:
            await self._publish(self.run_id)
        return AiRunStatus.WAITING

    async def _publish(self, run_id: uuid.UUID) -> None:
        try:
            await self.deps.publish(AiRunMessage(run_id=run_id, org_id=self.org_id))
        except Exception as exc:  # noqa: BLE001 - ai.resume re-sends it after 2 minutes
            log.warning("ai run %s: publish failed (%s)", run_id, type(exc).__name__)

    async def _wake_parent(self) -> None:
        """A child ended: make its waiting parent due now and send it a message."""
        st = getattr(self, "st", None)
        parent = st.parent_run_id if st else None
        if parent is None:
            return
        async with tenant_session(self.org_id, None) as s:
            woke = await s.scalar(
                update(AiRunIndex)
                .where(AiRunIndex.run_id == parent, AiRunIndex.status == AiRunStatus.WAITING)
                .values(resume_at=func.now(), dispatched_at=func.now())
                .returning(AiRunIndex.run_id)
            )
        if woke is not None:
            await self._publish(parent)


async def _verify_provider(provider: LlmProvider) -> VerifyOutcome:
    try:
        return await provider.verify()
    except ProviderError as exc:
        if exc.kind is ProviderErrorKind.AUTH_FAILED:
            return VerifyOutcome(status=VerifyStatus.INVALID, error_code="auth_failed")
        return VerifyOutcome(status=VerifyStatus.ERROR, error_code=exc.kind.value)
    except Exception as exc:  # noqa: BLE001
        log.warning("ai verify raised %s", type(exc).__name__)
        return VerifyOutcome(status=VerifyStatus.ERROR, error_code="internal_error")


async def _save_verify(
    org_id: uuid.UUID,
    config_id: uuid.UUID,
    key_version: int,
    verdict: VerifyOutcome,
    *,
    inline: bool = False,
) -> None:
    """Record the verdict for exactly this key version (a newer key keeps its own state)."""
    async with tenant_session(org_id, None) as s:
        updated = await s.scalar(
            update(AiProviderConfig)
            .where(AiProviderConfig.id == config_id, AiProviderConfig.key_version == key_version)
            .values(
                verify_status=verdict.status.value,
                verified_at=func.now(),
                last_error_code=verdict.error_code,
            )
            .returning(AiProviderConfig.provider)
        )
        if updated is None:
            return
        valid = verdict.status is VerifyStatus.VALID
        audit.record(
            s,
            action="ai.provider_verified" if valid else "ai.provider_verify_failed",
            org_id=org_id,
            actor_id=None,
            target_type="ai_provider_config",
            target_id=config_id,
            details={
                "provider": updated,
                "key_version": key_version,
                "verify_status": verdict.status.value,
                "error_code": verdict.error_code,
                "inline": inline,
            },
        )


# --- task handlers -------------------------------------------------------------------------


async def handle_run(
    message: Mapping[str, Any], deps: AnalystDeps | None = None
) -> AiRunStatus | None:
    """Make progress on one run (at most one provider call). Returns the status it left the
    run in, or None when nothing changed (invalid / duplicate / final / org mismatch)."""
    try:
        msg = AiRunMessage.model_validate(message)
    except ValidationError:
        _drop("invalid message", message)
        return None
    async with tenant_session(None, None) as s:
        row = (
            await s.execute(
                select(AiRunIndex.organization_id, AiRunIndex.status).where(
                    AiRunIndex.run_id == msg.run_id
                )
            )
        ).first()
    if row is None or row.organization_id != msg.org_id:
        _drop("unknown run or org mismatch", message)
        return None
    org_id: uuid.UUID = row.organization_id
    if row.status not in RUN_ACTIVE:
        return None  # already final: a redelivered or duplicated message

    token = secrets.token_hex(16)
    async with tenant_session(None, None) as s:
        leased = await s.scalar(
            update(AiRunIndex)
            .where(
                AiRunIndex.run_id == msg.run_id,
                AiRunIndex.organization_id == org_id,
                AiRunIndex.status.in_(RUN_ACTIVE),
                or_(AiRunIndex.lease_until.is_(None), AiRunIndex.lease_until < func.now()),
                # A waiting run is not due before its resume_at: an early duplicate exits.
                or_(
                    AiRunIndex.status != AiRunStatus.WAITING,
                    AiRunIndex.resume_at.is_(None),
                    AiRunIndex.resume_at <= func.now() + RESUME_SLACK,
                ),
            )
            .values(lease_until=func.now() + LEASE, lease_owner=token)
            .returning(AiRunIndex.run_id)
        )
    if leased is None:
        log.info("ai run %s: lease held or not due", msg.run_id)
        return None

    work = _Work(deps or get_deps(), org_id, msg.run_id, token)
    renewer = asyncio.create_task(work.renew_forever())
    try:
        return await work.run()
    except Exception as exc:  # noqa: BLE001 - ai.resume retries; the deadline bounds it
        log.error("ai run %s: internal error (%s)", msg.run_id, type(exc).__name__)
        return None
    finally:
        renewer.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await renewer
        with contextlib.suppress(Exception):
            await work.release()


async def handle_resume(
    message: Mapping[str, Any] | None = None, deps: AnalystDeps | None = None
) -> int:
    """Re-send `ai.run` for due runs (the M4 RT8 rules): `waiting` with `resume_at <= now()`
    (once, then at most every 2 minutes), or `queued` / `running` with a free or expired lease
    and `dispatched_at` older than 2 minutes. Bumps `dispatched_at`. Returns how many it sent."""
    try:
        AiResumeMessage.model_validate(message or {})
    except ValidationError:
        _drop("invalid message", message or {})
        return 0
    stale = func.now() - REDISPATCH_AFTER
    lease_free = or_(AiRunIndex.lease_until.is_(None), AiRunIndex.lease_until < func.now())
    never_or_stale = or_(AiRunIndex.dispatched_at.is_(None), AiRunIndex.dispatched_at < stale)
    due = (
        select(AiRunIndex.run_id)
        .where(
            or_(
                and_(
                    AiRunIndex.status == AiRunStatus.WAITING,
                    AiRunIndex.resume_at <= func.now(),
                    lease_free,
                    or_(never_or_stale, AiRunIndex.dispatched_at < AiRunIndex.resume_at),
                ),
                and_(
                    AiRunIndex.status.in_((AiRunStatus.QUEUED, AiRunStatus.RUNNING)),
                    lease_free,
                    never_or_stale,
                ),
            )
        )
        .order_by(AiRunIndex.dispatched_at.asc().nulls_first())
        .limit(RESUME_BATCH)
        .with_for_update(skip_locked=True)
    )
    async with tenant_session(None, None) as s:
        rows = (
            await s.execute(
                update(AiRunIndex)
                .where(AiRunIndex.run_id.in_(due.scalar_subquery()))
                .values(dispatched_at=func.now())
                .returning(AiRunIndex.run_id, AiRunIndex.organization_id)
            )
        ).all()
    if not rows:
        return 0
    deps = deps or get_deps()
    sent = 0
    for run_id, org_id in rows:
        try:
            await deps.publish(AiRunMessage(run_id=run_id, org_id=org_id))
            sent += 1
        except Exception as exc:  # noqa: BLE001 - retried on the next beat
            log.warning("ai.resume: publish failed for run %s (%s)", run_id, type(exc).__name__)
    log.info("ai.resume re-sent %d runs", sent)
    return sent


async def handle_verify(message: Mapping[str, Any], deps: AnalystDeps | None = None) -> None:
    """`ai.verify {org_id, provider, key_version}`: open the stored key, call
    `provider.verify()`, record `verify_status` / `verified_at` / `last_error_code` (audited
    with a NULL actor). Skipped when the stored key version differs (a newer key has its own
    message) and deduped per key version (broker SET NX)."""
    try:
        msg = AiVerifyMessage.model_validate(message)
    except ValidationError:
        _drop("invalid verify message", message)
        return
    deps = deps or get_deps()
    async with tenant_session(msg.org_id, None) as s:
        row = await s.scalar(
            select(AiProviderConfig).where(
                AiProviderConfig.organization_id == msg.org_id,
                AiProviderConfig.provider == msg.provider.value,
            )
        )
        config_id = row.id if row is not None else None
        sealed = _sealed(row) if row is not None else None
        model = row.model if row is not None else None
    if config_id is None or sealed is None or sealed.key_version != msg.key_version:
        log.info("ai.verify %s: no matching key stored", msg.provider.value)
        return
    try:
        claimed = await deps.limiter.claim_verify(msg.provider, msg.org_id, msg.key_version)
    except LimiterUnavailable:
        log.warning("ai.verify %s: limiter unavailable, check skipped", msg.provider.value)
        return
    if not claimed:
        log.info("ai.verify %s: duplicate check skipped", msg.provider.value)
        return
    available, _reason = provider_available(deps.settings, msg.provider)
    if not available:
        verdict = VerifyOutcome(status=VerifyStatus.ERROR, error_code="provider_unavailable")
    else:
        try:
            key = open_sealed(sealed, msg.org_id, msg.provider.value, deps.private_keys)
        except UnsealError as exc:
            verdict = VerifyOutcome(status=VerifyStatus.ERROR, error_code=exc.code[:64])
        else:
            try:
                provider = deps.build_provider(
                    msg.provider,
                    api_key=key,
                    model=model or AI_CATALOG[msg.provider].default_model,
                    settings=deps.settings,
                    org_options={},
                )
            except Exception as exc:  # noqa: BLE001
                log.warning("ai.verify: provider unavailable (%s)", type(exc).__name__)
                verdict = VerifyOutcome(
                    status=VerifyStatus.ERROR, error_code="provider_unavailable"
                )
            else:
                try:
                    verdict = await _verify_provider(provider)
                finally:
                    with contextlib.suppress(Exception):
                        await provider.aclose()
    await _save_verify(msg.org_id, config_id, msg.key_version, verdict)
    log.info("ai.verify %s: %s", msg.provider.value, verdict.status.value)


__all__ = [
    "AnalystDeps",
    "check_startup",
    "get_deps",
    "handle_resume",
    "handle_run",
    "handle_verify",
]
