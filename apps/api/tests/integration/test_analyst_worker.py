"""The AI analyst worker (M5 phase 2): lease, deadline, call cap, typed outcomes, repair,
canary, budgets (day / tree / platform, day-key seeding), limiter, key unsealing and lazy
re-seal, incident map-reduce, digest reuse, `ai.resume`, `ai.verify`, and the log hygiene.

The cross-phase entry points are the phase-1 doubles (`tests/ai_doubles.py`): the prompt is
`trivial_render`, the verifier `PassThroughVerifier`, the reduce `passthrough_reduce`, and
the provider a scripted in-process `LlmProvider` built by an injected `build_provider`. The
limiter and the budget run for real on the broker, as the `analyst` user.
"""

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import re
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import pytest_asyncio
from pydantic import SecretStr
from redis.asyncio import Redis
from sqlalchemy import event, func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.db import get_engine
from app.core.tenancy import tenant_session
from app.modules.ai.budget import Budget
from app.modules.ai.contracts import (
    AiProviderName,
    AiRunStatus,
    AiScope,
    AiTask,
    ContextRef,
    FrozenContext,
    OutputFlag,
    ProviderError,
    ProviderErrorKind,
    ProviderRequest,
    ProviderResult,
    ProviderUsage,
    RefKind,
    RunScope,
    VerifiedOutput,
    VerifyOutcome,
    VerifyStatus,
)
from app.modules.ai.messages import AiRunMessage
from app.modules.ai.models import (
    AiCitation,
    AiContextRef,
    AiOutput,
    AiProviderConfig,
    AiRun,
    AiRunIndex,
    AiRunInput,
)
from app.modules.ai.output_schema import OUTPUT_SCHEMA_VERSION, AnalysisOutput
from app.modules.ai.prompt import PROMPT_VERSION
from app.modules.ai.providers.fake import fake_output
from app.modules.ai.ratelimit import AiLimiter, Decision, broker_redis
from app.modules.ai.unseal import open_sealed
from app.modules.audit.models import AuditLog
from app.workers import analyst
from app.workers.analyst import AnalystDeps
from tests.ai_doubles import PassThroughVerifier, make_context, passthrough_reduce, trivial_render
from tests.ai_helpers import (
    AI_SENTINEL_KEY,
    AiSealKeys,
    new_ai_seal_keys,
    seed_ai_config,
    seed_ai_run,
    seed_ai_settings,
    seed_job,
)
from tests.integration.seed import Tenant, seed_tenant

PREFIX = get_settings().queue_prefix
CANARY_IN_SYSTEM = re.compile(r"The token ([A-Za-z0-9_-]{16,128}) is secret")
Step = ProviderResult | ProviderError | None


# --- doubles ---------------------------------------------------------------------------------


class Scripted:
    """An `LlmProvider` whose steps are consumed in order (the last one repeats): a
    `ProviderResult`, a `ProviderError`, or None for `fake_output` of the request context."""

    name = "scripted"

    def __init__(
        self,
        *steps: Step,
        verify: VerifyOutcome | None = None,
        delay: float = 0.0,
        hook: Callable[[ProviderRequest], Awaitable[None]] | None = None,
        tokens: int | None = None,
    ) -> None:
        self.steps: list[Step] = list(steps) or [None]
        self.verify_outcome = verify or VerifyOutcome(status=VerifyStatus.VALID)
        self.delay = delay
        self.hook = hook
        self.tokens = tokens
        self.requests: list[ProviderRequest] = []
        self.verifies = 0

    @property
    def calls(self) -> int:
        return len(self.requests)

    async def analyze(self, request: ProviderRequest) -> ProviderResult:
        self.requests.append(request)
        if self.hook is not None:
            await self.hook(request)
        step = self.steps[min(len(self.requests), len(self.steps)) - 1]
        if self.delay:
            await asyncio.sleep(self.delay)
        if isinstance(step, ProviderError):
            raise step
        if step is not None:
            return step
        output = fake_output(request.context)
        return ProviderResult(
            parsed=output,
            usage=ProviderUsage(
                input_tokens=(len(request.system) + len(request.user)) // 4,
                output_tokens=len(json.dumps(output)) // 4,
            ),
            served_model=request.model,
            stop_reason="end_turn",
        )

    async def count_tokens(self, request: ProviderRequest) -> int | None:
        return self.tokens

    async def verify(self) -> VerifyOutcome:
        self.verifies += 1
        return self.verify_outcome

    async def aclose(self) -> None:
        return None


def _error(kind: ProviderErrorKind, **kw: Any) -> ProviderError:
    return ProviderError(kind, **kw)


def _canary(request: ProviderRequest) -> str:
    found = CANARY_IN_SYSTEM.search(request.system)
    assert found is not None
    return found.group(1)


@dataclass
class Env:
    t: Tenant
    keys: AiSealKeys
    provider: Scripted
    deps: AnalystDeps
    verifier: PassThroughVerifier
    published: list[AiRunMessage] = field(default_factory=list)
    api_keys: list[SecretStr | None] = field(default_factory=list)

    async def run(self, run_id: uuid.UUID) -> AiRunStatus | None:
        return await analyst.handle_run(_msg(self.t, run_id), self.deps)


def _msg(t: Tenant, run_id: uuid.UUID) -> dict[str, str]:
    return {"run_id": str(run_id), "org_id": str(t.org_id)}


def _settings(keys: AiSealKeys, **over: Any) -> Settings:
    values: dict[str, Any] = {
        "env": "test",
        "ai_enabled": True,
        "ai_mock_enabled": True,
        "ai_seal_active_kid": keys.kid,
        "ai_seal_public_keys": {keys.kid: keys.public_b64},
        "ai_max_output_tokens": 1000,
        "ai_call_timeout_s": 30,
        "ai_max_calls_per_run": 3,
        "ai_platform_key_file": None,
        "ai_platform_provider": None,
    }
    values.update(over)
    return get_settings().model_copy(update=values)


@pytest_asyncio.fixture(loop_scope="session")
async def broker() -> AsyncIterator[Redis]:
    client = broker_redis(os.environ["TEST_BROKER_ANALYST_URL"])
    yield client
    await client.aclose()


def _env(
    broker: Redis,
    t: Tenant,
    keys: AiSealKeys,
    provider: Scripted,
    *,
    settings: Settings | None = None,
    verifier: Any = None,
    private_keys: Any = None,
    platform_key: SecretStr | None = None,
    limiter: AiLimiter | None = None,
) -> Env:
    env = Env(t, keys, provider, deps=None, verifier=verifier or PassThroughVerifier())  # type: ignore[arg-type]

    async def publish(message: AiRunMessage) -> None:
        env.published.append(message)

    def build(
        name: str, *, api_key: SecretStr | None, model: str, settings: Settings, org_options: Any
    ) -> Scripted:
        env.api_keys.append(api_key)
        return provider

    env.deps = AnalystDeps(
        settings=settings or _settings(keys),
        limiter=limiter or AiLimiter(broker, PREFIX),
        budget=Budget(broker, PREFIX),
        private_keys=private_keys if private_keys is not None else keys.private_keys,
        build_provider=build,
        render=trivial_render,
        repair_hint=lambda errors: "REPAIR: " + "; ".join(errors),
        verify_output=env.verifier,
        build_reduce_context=passthrough_reduce,
        publish=publish,
        platform_key=platform_key,
    )
    return env


async def _tenant(broker: Redis, provider: Scripted, **kw: Any) -> tuple[Env, uuid.UUID]:
    """An org with AI enabled, a sealed mock key and one queued summarize_pcap run."""
    settings_fields = kw.pop("settings_fields", {})
    config_fields = kw.pop("config_fields", {})
    t = await seed_tenant(kw.pop("name", "alpha"))
    keys = new_ai_seal_keys()
    await seed_ai_settings(t, **settings_fields)
    await seed_ai_config(t, keys, **config_fields)
    env = _env(broker, t, keys, provider, **kw)
    return env, await seed_ai_run(t)


async def _run_row(t: Tenant, run_id: uuid.UUID) -> AiRun:
    async with tenant_session(t.org_id, t.owner_id) as s:
        return (await s.execute(select(AiRun).where(AiRun.id == run_id))).scalar_one()


async def _index(t: Tenant, run_id: uuid.UUID) -> AiRunIndex:
    async with tenant_session(t.org_id, t.owner_id) as s:
        return (await s.execute(select(AiRunIndex).where(AiRunIndex.run_id == run_id))).scalar_one()


async def _outputs(t: Tenant, run_id: uuid.UUID) -> list[AiOutput]:
    async with tenant_session(t.org_id, t.owner_id) as s:
        return list((await s.scalars(select(AiOutput).where(AiOutput.run_id == run_id))).all())


async def _citations(t: Tenant, run_id: uuid.UUID) -> list[AiCitation]:
    async with tenant_session(t.org_id, t.owner_id) as s:
        return list((await s.scalars(select(AiCitation).where(AiCitation.run_id == run_id))).all())


async def _config(t: Tenant, provider: str = "mock") -> AiProviderConfig:
    async with tenant_session(t.org_id, t.owner_id) as s:
        return (
            await s.execute(select(AiProviderConfig).where(AiProviderConfig.provider == provider))
        ).scalar_one()


async def _make_due(t: Tenant, run_id: uuid.UUID) -> None:
    async with tenant_session(t.org_id, None) as s:
        await s.execute(
            update(AiRunIndex)
            .where(AiRunIndex.run_id == run_id)
            .values(resume_at=func.now() - timedelta(seconds=1))
        )


async def _status(t: Tenant, run_id: uuid.UUID) -> tuple[str, str | None, str]:
    run = await _run_row(t, run_id)
    index = await _index(t, run_id)
    return run.status, run.error_code, index.status


async def _seconds_until_resume(t: Tenant, run_id: uuid.UUID) -> float:
    index = await _index(t, run_id)
    assert index.resume_at is not None
    return (index.resume_at - datetime.now(UTC)).total_seconds()


async def _seed_incident(
    t: Tenant,
    jobs: Sequence[uuid.UUID],
    *,
    deadline_s: int = 1200,
    child_deadline_s: int | None = None,
) -> tuple[uuid.UUID, list[uuid.UUID]]:
    """An investigation-scoped incident_summary parent (V1, K1) and one queued job_digest
    child per job (the children carry the parent's deadline, as phase 7 creates them)."""
    scope = RunScope(
        scope=AiScope.INVESTIGATION, job_ids=tuple(jobs), investigation_id=t.investigation_id
    )
    ctx = make_context(
        task=AiTask.INCIDENT_SUMMARY,
        job_id=jobs[0],
        scope=scope,
        items=(
            (RefKind.INVESTIGATION, {"title": "Incident case about periodic beaconing"}),
            (RefKind.EVIDENCE, {"filename": "capture.pcap", "sha256": "a" * 64}),
        ),
    )
    parent = uuid.uuid4()
    deadline = datetime.now(UTC) + timedelta(seconds=deadline_s)
    async with tenant_session(t.org_id, t.owner_id) as s:
        s.add(
            AiRun(
                id=parent,
                organization_id=t.org_id,
                task=AiTask.INCIDENT_SUMMARY,
                scope="investigation",
                investigation_id=t.investigation_id,
                provider="mock",
                model="mock-1",
                prompt_version=PROMPT_VERSION,
                output_schema=OUTPUT_SCHEMA_VERSION,
                context_sha256=ctx.sha256,
                context_stats=ctx.stats.model_dump(mode="json"),
                requested_by=t.owner_id,
                deadline_at=deadline,
            )
        )
        await s.flush()
        s.add(
            AiRunIndex(
                run_id=parent,
                organization_id=t.org_id,
                status="queued",
                deadline_at=deadline,
                dispatched_at=datetime.now(UTC),
            )
        )
        s.add(
            AiRunInput(
                run_id=parent,
                stage="base",
                organization_id=t.org_id,
                context=ctx.model_dump(mode="json", exclude={"pseudonym_map"}),
                context_sha256=ctx.sha256,
                pseudonym_map=ctx.pseudonym_map,
            )
        )
        for ref in ctx.refs:
            s.add(
                AiContextRef(
                    run_id=parent,
                    label=ref.label,
                    organization_id=t.org_id,
                    stage="base",
                    kind=ref.kind,
                    ref_table=ref.ref_table,
                    ref_id=ref.ref_id,
                    job_id=None,
                    fields_sha256=ref.fields_sha256,
                )
            )
    children = [
        await seed_ai_run(
            t,
            job_id=job,
            task=AiTask.JOB_DIGEST,
            parent_run_id=parent,
            deadline_s=deadline_s if child_deadline_s is None else child_deadline_s,
        )
        for job in jobs
    ]
    return parent, children


# --- happy path, messages, lease ------------------------------------------------------------


async def test_happy_path_persists_output_citations_usage_and_metrics(broker: Redis) -> None:
    env, run_id = await _tenant(broker, Scripted())
    assert await env.run(run_id) is AiRunStatus.COMPLETED
    run = await _run_row(env.t, run_id)
    index = await _index(env.t, run_id)
    assert (run.status, run.error_code, index.status) == ("completed", None, "completed")
    assert (index.calls, index.lease_until, index.lease_owner) == (1, None, None)
    assert run.started_at is not None and run.finished_at is not None
    assert env.api_keys == [SecretStr(AI_SENTINEL_KEY)]
    (request,) = env.provider.requests
    assert request.model == "mock-1" and request.max_output_tokens == 1000
    assert request.context is not None and request.context.sha256 == run.context_sha256

    usage = ProviderUsage.model_validate(run.usage)
    assert usage.total > 0
    assert (run.cost_micros, run.price_version, run.served_model) == (0, "2026-11-05", "mock-1")
    canary = _canary(request)
    assert run.metrics["canary_sha256"] == hashlib.sha256(canary.encode()).hexdigest()
    assert run.metrics["repaired"] is False and run.metrics["usage_unknown"] is False

    (output,) = await _outputs(env.t, run_id)
    assert AnalysisOutput.model_validate(output.body) == AnalysisOutput.model_validate(
        fake_output(request.context)
    )
    assert output.flags == []
    citations = await _citations(env.t, run_id)
    assert len(citations) == run.metrics["citations_total"] > 0
    assert {c.claim_status for c in citations} == {"supported"}
    assert all(c.output_id == output.id and c.status == "verified" for c in citations)
    stored = json.dumps([output.body, output.verification, run.metrics, run.usage])
    assert canary not in stored and AI_SENTINEL_KEY not in stored
    # The day reservation was settled to the actual usage.
    assert await env.deps.budget.used_today(env.t.org_id) == usage.total


async def test_org_mismatch_unknown_runs_and_bad_messages_are_dropped(broker: Redis) -> None:
    env, run_id = await _tenant(broker, Scripted())
    other = await seed_tenant("bravo")
    bad = [
        _msg(other, run_id),
        {"run_id": str(uuid.uuid4()), "org_id": str(env.t.org_id)},
        {"run_id": "x", "context": "secret"},
        {"run_id": str(run_id), "org_id": str(env.t.org_id), "extra": 1},
    ]
    for message in bad:
        assert await analyst.handle_run(message, env.deps) is None
    assert env.provider.calls == 0
    assert await _status(env.t, run_id) == ("queued", None, "queued")


async def test_redelivery_and_concurrent_replicas_make_one_call(broker: Redis) -> None:
    env, run_id = await _tenant(broker, Scripted(delay=0.3))
    first, second = await asyncio.gather(env.run(run_id), env.run(run_id))
    assert {first, second} == {AiRunStatus.COMPLETED, None}
    assert await env.run(run_id) is None  # redelivered after the end: final, nothing
    assert env.provider.calls == 1
    assert len(await _outputs(env.t, run_id)) == 1


async def test_a_live_lease_held_elsewhere_exits(broker: Redis) -> None:
    env, run_id = await _tenant(broker, Scripted())
    async with tenant_session(env.t.org_id, None) as s:
        await s.execute(
            update(AiRunIndex)
            .where(AiRunIndex.run_id == run_id)
            .values(lease_until=func.now() + timedelta(seconds=60), lease_owner="other")
        )
    assert await env.run(run_id) is None
    assert env.provider.calls == 0
    assert (await _index(env.t, run_id)).lease_owner == "other"


async def test_the_lease_is_renewed_during_a_long_call(broker: Redis) -> None:
    seen: list[datetime] = []

    async def watch(request: ProviderRequest) -> None:
        for _ in range(3):
            index = await _index(env.t, run_id)
            assert index.lease_until is not None
            seen.append(index.lease_until)
            await asyncio.sleep(0.25)

    env, run_id = await _tenant(broker, Scripted(hook=watch))
    env.deps.lease_renew_s = 0.1
    assert await env.run(run_id) is AiRunStatus.COMPLETED
    assert seen[-1] > seen[0]


async def test_a_waiting_run_is_not_due_before_resume_at(broker: Redis) -> None:
    env, run_id = await _tenant(
        broker, Scripted(_error(ProviderErrorKind.RATE_LIMITED, retry_after_s=60), None)
    )
    assert await env.run(run_id) is AiRunStatus.WAITING
    assert await env.run(run_id) is None  # an early duplicate exits
    assert env.provider.calls == 1


# --- deadline, call cap, gates --------------------------------------------------------------


async def test_past_the_deadline_fails_without_a_call(broker: Redis) -> None:
    env, _ = await _tenant(broker, Scripted())
    late = await seed_ai_run(env.t, deadline_s=-5)
    assert await env.run(late) is AiRunStatus.FAILED
    assert await _status(env.t, late) == ("failed", "deadline", "failed")
    assert env.provider.calls == 0


async def test_children_inherit_the_parent_deadline(broker: Redis) -> None:
    env, _ = await _tenant(broker, Scripted())
    job = await seed_job(env.t)
    # The parent's deadline passed; the child's own row still has 20 minutes.
    _parent, (child,) = await _seed_incident(env.t, [job], deadline_s=-60, child_deadline_s=1200)
    assert await env.run(child) is AiRunStatus.FAILED
    assert await _status(env.t, child) == ("failed", "deadline", "failed")
    assert env.provider.calls == 0


async def test_the_call_cap_ends_the_run(broker: Redis) -> None:
    env, run_id = await _tenant(broker, Scripted())
    async with tenant_session(env.t.org_id, None) as s:
        await s.execute(update(AiRunIndex).where(AiRunIndex.run_id == run_id).values(calls=3))
    assert await env.run(run_id) is AiRunStatus.FAILED
    assert await _status(env.t, run_id) == ("failed", "provider_error", "failed")
    assert env.provider.calls == 0


@pytest.mark.parametrize(
    ("case", "code"),
    [
        ("org_disabled", "ai_disabled"),
        ("platform_disabled", "ai_disabled"),
        ("provider_disabled", "provider_disabled"),
        ("mock_unavailable", "provider_unavailable"),
        ("prod_mock", "provider_unavailable"),
    ],
)
async def test_org_and_provider_state_is_rechecked(broker: Redis, case: str, code: str) -> None:
    kw: dict[str, Any] = {}
    if case == "org_disabled":
        kw["settings_fields"] = {"enabled": False}
    if case == "provider_disabled":
        kw["config_fields"] = {"enabled": False}
    env, run_id = await _tenant(broker, Scripted(), **kw)
    if case == "platform_disabled":
        env.deps.settings = _settings(env.keys, ai_enabled=False)
    if case == "mock_unavailable":
        env.deps.settings = _settings(env.keys, ai_mock_enabled=False)
    if case == "prod_mock":
        env.deps.settings = _settings(env.keys, env="prod")
    assert await env.run(run_id) is AiRunStatus.FAILED
    assert await _status(env.t, run_id) == ("failed", code, "failed")
    assert env.provider.calls == 0


# --- outcome table ----------------------------------------------------------------------------


async def test_rate_limited_waits_for_the_cooldown(broker: Redis) -> None:
    env, run_id = await _tenant(
        broker, Scripted(_error(ProviderErrorKind.RATE_LIMITED, retry_after_s=5), None)
    )
    assert await env.run(run_id) is AiRunStatus.WAITING
    assert await _status(env.t, run_id) == ("waiting", None, "waiting")
    assert 3 < await _seconds_until_resume(env.t, run_id) <= 6
    # Not billed: the reservation is released.
    assert await env.deps.budget.used_today(env.t.org_id) == 0
    acquired = await env.deps.limiter.acquire("mock", env.t.org_id, 600)
    assert acquired.decision is Decision.COOLDOWN and 3 < acquired.wait_s <= 5
    # Another run of the org waits for the cooldown without a call.
    other = await seed_ai_run(env.t)
    assert await env.run(other) is AiRunStatus.WAITING
    assert env.provider.calls == 1


async def test_rate_limited_without_retry_after_waits_for_the_next_minute(broker: Redis) -> None:
    env, run_id = await _tenant(broker, Scripted(_error(ProviderErrorKind.RATE_LIMITED)))
    assert await env.run(run_id) is AiRunStatus.WAITING
    assert 0 < await _seconds_until_resume(env.t, run_id) <= 61


async def test_overloaded_backs_off_then_fails(broker: Redis) -> None:
    env, run_id = await _tenant(broker, Scripted(_error(ProviderErrorKind.OVERLOADED)))
    assert await env.run(run_id) is AiRunStatus.WAITING
    assert (await _index(env.t, run_id)).attempts == 1
    assert 25 < await _seconds_until_resume(env.t, run_id) <= 31
    await _make_due(env.t, run_id)
    assert await env.run(run_id) is AiRunStatus.WAITING
    assert (await _index(env.t, run_id)).attempts == 2
    assert 55 < await _seconds_until_resume(env.t, run_id) <= 61
    await _make_due(env.t, run_id)
    assert await env.run(run_id) is AiRunStatus.FAILED  # the third call used the last one
    assert await _status(env.t, run_id) == ("failed", "overloaded", "failed")
    assert env.provider.calls == 3


async def test_spend_limit_fails_and_parks_the_provider_until_midnight(broker: Redis) -> None:
    env, run_id = await _tenant(broker, Scripted(_error(ProviderErrorKind.SPEND_LIMIT)))
    assert await env.run(run_id) is AiRunStatus.FAILED
    assert await _status(env.t, run_id) == ("failed", "spend_limit", "failed")
    acquired = await env.deps.limiter.acquire("mock", env.t.org_id, 600)
    assert acquired.decision is Decision.COOLDOWN
    midnight = (datetime.now(UTC) + timedelta(days=1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    assert abs(acquired.wait_s - (midnight - datetime.now(UTC)).total_seconds()) < 5


@pytest.mark.parametrize(
    ("verdict", "code", "verify_status"),
    [
        (VerifyStatus.INVALID, "auth_failed", "invalid"),
        (VerifyStatus.VALID, "provider_error", "unverified"),
        (VerifyStatus.ERROR, "auth_failed", "unverified"),
    ],
)
async def test_auth_failed_verifies_inline(
    broker: Redis, verdict: VerifyStatus, code: str, verify_status: str
) -> None:
    provider = Scripted(
        _error(ProviderErrorKind.AUTH_FAILED, http_status=401),
        verify=VerifyOutcome(
            status=verdict, error_code=None if verdict is VerifyStatus.VALID else "auth_failed"
        ),
    )
    env, run_id = await _tenant(broker, provider)
    assert await env.run(run_id) is AiRunStatus.FAILED
    assert await _status(env.t, run_id) == ("failed", code, "failed")
    assert provider.verifies == 1
    assert (await _config(env.t)).verify_status == verify_status


@pytest.mark.parametrize(
    "step",
    [
        _error(ProviderErrorKind.REFUSED, category="cyber", request_sent=True),
        ProviderResult(
            parsed={},
            usage=ProviderUsage(input_tokens=10, output_tokens=2),
            served_model="mock-1",
            stop_reason="refusal",
            refusal_category="cyber",
        ),
    ],
)
async def test_refusals_are_final_with_their_category(broker: Redis, step: Step) -> None:
    env, run_id = await _tenant(broker, Scripted(step))
    assert await env.run(run_id) is AiRunStatus.REFUSED
    run = await _run_row(env.t, run_id)
    assert (run.status, run.error_code) == ("refused", "refused")
    assert run.metrics["refusal_category"] == "cyber"
    assert env.provider.calls == 1
    # A refusal error carries no usage and is not billed: the reservation is released. A
    # refusal result carries its usage: settled to it.
    expected = step.usage.total if isinstance(step, ProviderResult) else 0
    assert ProviderUsage.model_validate(run.usage).total == expected
    assert run.metrics["usage_unknown"] is False
    assert await env.deps.budget.used_today(env.t.org_id) == expected


@pytest.mark.parametrize(
    ("step", "charged"),
    [
        (_error(ProviderErrorKind.TIMEOUT, request_sent=True), True),
        (_error(ProviderErrorKind.TRANSPORT, request_sent=True), True),
        (_error(ProviderErrorKind.MAX_TOKENS, request_sent=True), True),
        (_error(ProviderErrorKind.PROVIDER_ERROR, http_status=500, request_sent=True), True),
        (_error(ProviderErrorKind.TIMEOUT, request_sent=False), False),
        (_error(ProviderErrorKind.TRANSPORT, request_sent=False), False),
        (_error(ProviderErrorKind.REFUSED, category="bio", request_sent=True), False),
        (_error(ProviderErrorKind.RATE_LIMITED, http_status=429, request_sent=True), False),
        (_error(ProviderErrorKind.OVERLOADED, http_status=529, request_sent=True), False),
        (_error(ProviderErrorKind.SPEND_LIMIT, http_status=429, request_sent=True), False),
        (_error(ProviderErrorKind.AUTH_FAILED, http_status=401, request_sent=True), False),
        (_error(ProviderErrorKind.BAD_REQUEST, http_status=400, request_sent=True), False),
    ],
)
async def test_errors_without_usage_settle_the_budget(
    broker: Redis, step: ProviderError, charged: bool
) -> None:
    """Errors carry no usage: an unbilled one releases the reservation, one that may have
    been billed (sent, then lost) keeps it charged and flags the usage as unknown (RT2)."""
    env, run_id = await _tenant(broker, Scripted(step))
    await env.run(run_id)
    run = await _run_row(env.t, run_id)
    total = ProviderUsage.model_validate(run.usage).total
    used = await env.deps.budget.used_today(env.t.org_id)
    if charged:
        assert total > 1000 and used == total  # estimate + max_output_tokens
        assert run.metrics["usage_unknown"] is True
    else:
        assert total == 0 and used == 0
        assert run.metrics.get("usage_unknown", False) is False


@pytest.mark.parametrize(
    ("step", "code"),
    [
        (_error(ProviderErrorKind.MAX_TOKENS, request_sent=True), "max_tokens"),
        (
            ProviderResult(
                parsed={},
                usage=ProviderUsage(input_tokens=10, output_tokens=1000),
                served_model="mock-1",
                stop_reason="max_tokens",
            ),
            "max_tokens",
        ),
        (_error(ProviderErrorKind.CONTEXT_TOO_LARGE, http_status=400), "context_too_large"),
        (_error(ProviderErrorKind.BAD_REQUEST, http_status=400), "provider_error"),
        (_error(ProviderErrorKind.PROVIDER_ERROR, http_status=500), "provider_error"),
    ],
)
async def test_terminal_outcomes(broker: Redis, step: Step, code: str) -> None:
    env, run_id = await _tenant(broker, Scripted(step))
    assert await env.run(run_id) is AiRunStatus.FAILED
    assert await _status(env.t, run_id) == ("failed", code, "failed")
    assert env.provider.calls == 1


async def test_an_adapter_bug_is_a_typed_provider_error(broker: Redis) -> None:
    async def boom(request: ProviderRequest) -> None:
        raise RuntimeError("adapter bug with secret details")

    env, run_id = await _tenant(broker, Scripted(hook=boom))
    env.deps.settings = _settings(env.keys, ai_max_calls_per_run=1)
    assert await env.run(run_id) is AiRunStatus.FAILED
    assert await _status(env.t, run_id) == ("failed", "provider_error", "failed")


async def test_timeouts_after_the_request_was_sent_stay_charged_and_cap_at_three_calls(
    broker: Redis,
) -> None:
    env, run_id = await _tenant(
        broker, Scripted(_error(ProviderErrorKind.TIMEOUT, request_sent=True))
    )
    assert await env.run(run_id) is AiRunStatus.WAITING
    assert 5 < await _seconds_until_resume(env.t, run_id) <= 11
    run = await _run_row(env.t, run_id)
    assert run.metrics["usage_unknown"] is True
    charged = ProviderUsage.model_validate(run.usage).total
    assert charged > 1000  # estimate + max_output_tokens, assumed billed
    assert await env.deps.budget.used_today(env.t.org_id) == charged
    for _ in range(2):
        await _make_due(env.t, run_id)
        await env.run(run_id)
    assert await _status(env.t, run_id) == ("failed", "provider_error", "failed")
    await _make_due(env.t, run_id)
    assert await env.run(run_id) is None
    assert env.provider.calls == 3  # never a fourth call
    assert (await _index(env.t, run_id)).calls == 3
    run = await _run_row(env.t, run_id)
    assert ProviderUsage.model_validate(run.usage).total == 3 * charged
    assert await env.deps.budget.used_today(env.t.org_id) == 3 * charged


async def test_a_transport_error_before_sending_is_not_charged(broker: Redis) -> None:
    env, run_id = await _tenant(
        broker, Scripted(_error(ProviderErrorKind.TRANSPORT, request_sent=False), None)
    )
    assert await env.run(run_id) is AiRunStatus.WAITING
    run = await _run_row(env.t, run_id)
    assert run.metrics.get("usage_unknown", False) is False
    assert await env.deps.budget.used_today(env.t.org_id) == 0
    await _make_due(env.t, run_id)
    assert await env.run(run_id) is AiRunStatus.COMPLETED


async def test_the_hard_call_timeout(broker: Redis) -> None:
    env, run_id = await _tenant(broker, Scripted(delay=7))
    env.deps.settings = _settings(env.keys, ai_call_timeout_s=5)
    assert await env.run(run_id) is AiRunStatus.WAITING
    assert (await _run_row(env.t, run_id)).metrics["usage_unknown"] is True


async def test_no_session_is_open_during_a_slow_call(
    broker: Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RT7: a call just below the timeout; no transaction is idle while it runs, and the
    output is persisted afterwards."""
    open_sessions = 0
    original = analyst.tenant_session

    @contextlib.asynccontextmanager
    async def counting(*args: Any, **kwargs: Any) -> AsyncIterator[AsyncSession]:
        nonlocal open_sessions
        open_sessions += 1
        try:
            async with original(*args, **kwargs) as session:
                yield session
        finally:
            open_sessions -= 1

    observed: list[tuple[int, int]] = []

    async def check(request: ProviderRequest) -> None:
        async with tenant_session(None, None) as s:
            idle = await s.scalar(
                text(
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                    "AND pid <> pg_backend_pid() AND state LIKE 'idle in transaction%'"
                )
            )
        observed.append((open_sessions, int(idle or 0)))

    monkeypatch.setattr(analyst, "tenant_session", counting)
    env, run_id = await _tenant(broker, Scripted(hook=check, delay=4.0))
    env.deps.settings = _settings(env.keys, ai_call_timeout_s=5)
    assert await env.run(run_id) is AiRunStatus.COMPLETED
    assert observed == [(0, 0)]
    assert len(await _outputs(env.t, run_id)) == 1


# --- repair, canary --------------------------------------------------------------------------


async def test_one_repair_retry_with_the_hint(broker: Redis) -> None:
    bad = ProviderResult(
        parsed={"observed": "not-a-list"},
        usage=ProviderUsage(input_tokens=50, output_tokens=5),
        served_model="mock-1",
        stop_reason="end_turn",
    )
    env, run_id = await _tenant(broker, Scripted(bad, None))
    assert await env.run(run_id) is AiRunStatus.WAITING
    assert [m.run_id for m in env.published] == [run_id]  # re-sent now, not after a beat
    run = await _run_row(env.t, run_id)
    assert run.metrics["repaired"] is True
    assert await env.run(run_id) is AiRunStatus.COMPLETED
    first, second = env.provider.requests
    assert "REPAIR:" not in first.user
    assert "REPAIR: observed" in second.user
    run = await _run_row(env.t, run_id)
    assert run.metrics["repaired"] is True
    assert ProviderUsage.model_validate(run.usage).input_tokens >= 50  # both calls counted
    assert (await _index(env.t, run_id)).calls == 2


async def test_invalid_output_twice_fails(broker: Redis) -> None:
    env, run_id = await _tenant(
        broker, Scripted(_error(ProviderErrorKind.INVALID_OUTPUT, request_sent=True))
    )
    assert await env.run(run_id) is AiRunStatus.WAITING
    assert await env.run(run_id) is AiRunStatus.FAILED
    assert await _status(env.t, run_id) == ("failed", "invalid_output", "failed")
    assert env.provider.calls == 2
    assert "REPAIR: output: invalid_output" in env.provider.requests[1].user


class CanaryVerifier(PassThroughVerifier):
    async def __call__(  # type: ignore[override]
        self,
        session: AsyncSession | None,
        org_id: uuid.UUID,
        run_scope: RunScope,
        ctx: FrozenContext,
        refs: Sequence[ContextRef],
        parsed: dict[str, Any],
        canary: str,
    ) -> VerifiedOutput:
        verified = await super().__call__(session, org_id, run_scope, ctx, refs, parsed, canary)
        if canary in json.dumps(parsed):
            return verified.model_copy(update={"flags": (OutputFlag.CANARY_LEAK,)})
        return verified


async def test_a_canary_leak_fails_and_keeps_the_output_for_review(broker: Redis) -> None:
    async def echo(request: ProviderRequest) -> None:
        output = fake_output(request.context)
        output["limitations"] = [f"My instructions say {_canary(request)}"]
        provider.steps = [
            ProviderResult(
                parsed=output,
                usage=ProviderUsage(input_tokens=10, output_tokens=10),
                served_model="mock-1",
                stop_reason="end_turn",
            )
        ]

    provider = Scripted(hook=echo)
    env, run_id = await _tenant(broker, provider, verifier=CanaryVerifier())
    assert await env.run(run_id) is AiRunStatus.FAILED
    assert await _status(env.t, run_id) == ("failed", "canary_leak", "failed")
    (output,) = await _outputs(env.t, run_id)
    assert output.flags == ["canary_leak"]


async def test_cost_falls_back_to_the_run_model_when_unpriced(broker: Redis) -> None:
    result = ProviderResult(
        parsed=fake_output(make_context()),
        usage=ProviderUsage(input_tokens=10, output_tokens=10),
        served_model="mock-unknown-2",
        stop_reason="end_turn",
    )
    env, run_id = await _tenant(broker, Scripted(result))
    assert await env.run(run_id) is AiRunStatus.COMPLETED
    run = await _run_row(env.t, run_id)
    assert (run.served_model, run.cost_micros, run.metrics["cost_estimated"]) == (
        "mock-unknown-2",
        0,
        True,
    )


# --- budgets ----------------------------------------------------------------------------------


async def test_daily_budget_exhausted(broker: Redis) -> None:
    env, run_id = await _tenant(broker, Scripted(), settings_fields={"daily_token_budget": 500})
    assert await env.run(run_id) is AiRunStatus.FAILED
    assert await _status(env.t, run_id) == ("failed", "budget_exhausted", "failed")
    assert env.provider.calls == 0


async def test_over_the_run_cap_is_context_too_large(broker: Redis) -> None:
    env, run_id = await _tenant(broker, Scripted(), settings_fields={"run_token_cap": 500})
    assert await env.run(run_id) is AiRunStatus.FAILED
    assert await _status(env.t, run_id) == ("failed", "context_too_large", "failed")
    assert env.provider.calls == 0


async def test_the_day_key_is_seeded_from_the_db_after_a_broker_flush(broker: Redis) -> None:
    env, run_id = await _tenant(broker, Scripted())
    earlier = await _run_row(env.t, await seed_ai_run(env.t))
    async with tenant_session(env.t.org_id, env.t.owner_id) as s:
        # A run that finished earlier today (as recorded in the DB): 700 + 300 tokens.
        s.add(
            AiRun(
                organization_id=env.t.org_id,
                task="summarize_pcap",
                scope="job",
                job_id=earlier.job_id,
                provider="mock",
                model="mock-1",
                prompt_version=PROMPT_VERSION,
                output_schema=OUTPUT_SCHEMA_VERSION,
                status="completed",
                context_sha256=earlier.context_sha256,
                usage={"input_tokens": 700, "output_tokens": 300},
                requested_by=env.t.owner_id,
                deadline_at=earlier.deadline_at,
                finished_at=datetime.now(UTC),
            )
        )
    assert await env.run(run_id) is AiRunStatus.COMPLETED
    first = ProviderUsage.model_validate((await _run_row(env.t, run_id)).usage).total
    assert await env.deps.budget.used_today(env.t.org_id) == 1000 + first
    # Broker restart: the counter is gone; the next reservation re-seeds it from the DB.
    await broker.delete(env.deps.budget.day_key(env.t.org_id))
    second_id = await seed_ai_run(env.t)
    assert await env.run(second_id) is AiRunStatus.COMPLETED
    second = ProviderUsage.model_validate((await _run_row(env.t, second_id)).usage).total
    assert await env.deps.budget.used_today(env.t.org_id) == 1000 + first + second


async def test_the_incident_tree_cap(broker: Redis) -> None:
    env, plain = await _tenant(broker, Scripted(), settings_fields={"incident_token_cap": 1})
    job = await seed_job(env.t)
    _parent, (child,) = await _seed_incident(env.t, [job])
    assert await env.run(child) is AiRunStatus.FAILED
    assert await _status(env.t, child) == ("failed", "budget_exhausted", "failed")
    assert await env.run(plain) is AiRunStatus.COMPLETED  # outside any tree


async def test_the_platform_key_and_its_global_ceiling(broker: Redis) -> None:
    platform = SecretStr("platform-dev-key-0000")
    env, run_id = await _tenant(
        broker, Scripted(), config_fields={"sealed": False}, platform_key=platform
    )
    env.deps.settings = _settings(
        env.keys,
        ai_platform_key_file="/run/secrets/ai_platform_key",
        ai_platform_provider=AiProviderName.MOCK,
        ai_platform_daily_tokens=100,
    )
    assert await env.run(run_id) is AiRunStatus.FAILED
    assert await _status(env.t, run_id) == ("failed", "budget_exhausted", "failed")
    env.deps.settings = _settings(
        env.keys,
        ai_platform_key_file="/run/secrets/ai_platform_key",
        ai_platform_provider=AiProviderName.MOCK,
        ai_platform_daily_tokens=100_000_000,
    )
    again = await seed_ai_run(env.t)
    assert await env.run(again) is AiRunStatus.COMPLETED
    assert env.api_keys == [platform, platform]
    # Only for its own provider: the mock then runs without a key.
    env.deps.settings = _settings(
        env.keys, ai_platform_key_file="/x", ai_platform_provider=AiProviderName.ANTHROPIC
    )
    third = await seed_ai_run(env.t)
    assert await env.run(third) is AiRunStatus.COMPLETED
    assert env.api_keys == [platform, platform, None]


async def test_the_limiter_fails_closed(broker: Redis) -> None:
    down = broker_redis("redis://127.0.0.1:1/0")
    try:
        env, run_id = await _tenant(broker, Scripted(), limiter=AiLimiter(down, PREFIX))
        assert await env.run(run_id) is AiRunStatus.WAITING
        assert 25 < await _seconds_until_resume(env.t, run_id) <= 31
        assert env.provider.calls == 0
    finally:
        await down.aclose()


# --- keys ---------------------------------------------------------------------------------


async def test_an_unseal_failure_is_auth_failed_with_verify_status_untouched(
    broker: Redis,
) -> None:
    env, run_id = await _tenant(
        broker, Scripted(), private_keys=new_ai_seal_keys("other-kid").private_keys
    )
    assert await env.run(run_id) is AiRunStatus.FAILED
    assert await _status(env.t, run_id) == ("failed", "auth_failed", "failed")
    assert (await _config(env.t)).verify_status == "unverified"
    assert env.provider.calls == 0


async def test_a_key_under_an_old_kid_is_resealed_under_the_active_one(broker: Redis) -> None:
    old = new_ai_seal_keys("old-ai-1")
    new = new_ai_seal_keys("new-ai-2")
    t = await seed_tenant("alpha")
    await seed_ai_settings(t)
    await seed_ai_config(t, old, version=4)
    env = _env(
        broker,
        t,
        new,
        Scripted(),
        private_keys={**old.private_keys, **new.private_keys},
    )
    run_id = await seed_ai_run(t)
    assert await env.run(run_id) is AiRunStatus.COMPLETED
    assert env.api_keys == [SecretStr(AI_SENTINEL_KEY)]
    config = await _config(t)
    assert (config.key_kid, config.key_version, config.key_last4) == (
        "new-ai-2",
        4,
        AI_SENTINEL_KEY[-4:],
    )
    sealed = analyst._sealed(config)
    assert sealed is not None
    assert open_sealed(sealed, t.org_id, "mock", new.private_keys).get_secret_value() == (
        AI_SENTINEL_KEY
    )


# --- incident map-reduce and digest reuse ----------------------------------------------------


async def test_an_incident_waits_for_its_children_then_reduces(broker: Redis) -> None:
    env, _ = await _tenant(broker, Scripted())
    jobs = [await seed_job(env.t), await seed_job(env.t)]
    parent, children = await _seed_incident(env.t, jobs)

    assert await env.run(parent) is AiRunStatus.WAITING
    assert 25 < await _seconds_until_resume(env.t, parent) <= 31
    assert env.provider.calls == 0

    assert await env.run(children[0]) is AiRunStatus.COMPLETED
    assert [m.run_id for m in env.published] == [parent]  # the child woke its parent
    assert await _seconds_until_resume(env.t, parent) <= 0
    assert await env.run(parent) is AiRunStatus.WAITING  # the second child is not final

    assert await env.run(children[1]) is AiRunStatus.COMPLETED
    assert await env.run(parent) is AiRunStatus.COMPLETED
    request = env.provider.requests[-1]
    assert request.context is not None
    labels = [item.label for item in request.context.items]
    assert labels[:2] == ["V1", "K1"]
    assert "J1:D1" in labels and "J2:D1" in labels
    async with tenant_session(env.t.org_id, env.t.owner_id) as s:
        stages = (
            await s.scalars(select(AiRunInput.stage).where(AiRunInput.run_id == parent))
        ).all()
        reduce_refs = (
            await s.scalars(
                select(AiContextRef.label).where(
                    AiContextRef.run_id == parent, AiContextRef.stage == "reduce"
                )
            )
        ).all()
    assert sorted(stages) == ["base", "reduce"]
    assert "J1:D1" in reduce_refs
    assert len(await _outputs(env.t, parent)) == 1


async def test_a_redelivered_parent_reuses_its_frozen_reduce_input(broker: Redis) -> None:
    env, _ = await _tenant(broker, Scripted())
    jobs = [await seed_job(env.t)]
    parent, (child,) = await _seed_incident(env.t, jobs)
    assert await env.run(child) is AiRunStatus.COMPLETED
    env.provider.steps = [_error(ProviderErrorKind.TIMEOUT, request_sent=True), None]
    env.provider.requests.clear()
    assert await env.run(parent) is AiRunStatus.WAITING
    await _make_due(env.t, parent)
    assert await env.run(parent) is AiRunStatus.COMPLETED
    first, second = env.provider.requests
    assert first.context is not None and second.context is not None
    assert first.context.sha256 == second.context.sha256


async def test_an_incident_is_partial_when_a_child_fails(broker: Redis) -> None:
    env, _ = await _tenant(
        broker, Scripted(None, _error(ProviderErrorKind.MAX_TOKENS, request_sent=True), None)
    )
    jobs = [await seed_job(env.t), await seed_job(env.t)]
    parent, children = await _seed_incident(env.t, jobs)
    assert await env.run(children[0]) is AiRunStatus.COMPLETED
    assert await env.run(children[1]) is AiRunStatus.FAILED
    assert await env.run(parent) is AiRunStatus.PARTIAL
    labels = [item.label for item in env.provider.requests[-1].context.items]  # type: ignore[union-attr]
    assert "J1:D1" in labels and not any(label.startswith("J2:") for label in labels)


async def test_an_incident_without_any_digest_fails(broker: Redis) -> None:
    env, _ = await _tenant(broker, Scripted(_error(ProviderErrorKind.REFUSED, category="cyber")))
    jobs = [await seed_job(env.t), await seed_job(env.t)]
    parent, children = await _seed_incident(env.t, jobs)
    for child in children:
        assert await env.run(child) is AiRunStatus.REFUSED
    assert await env.run(parent) is AiRunStatus.FAILED
    assert await _status(env.t, parent) == ("failed", "no_digest", "failed")
    assert env.provider.calls == 2


async def test_an_identical_digest_is_reused_without_a_call(broker: Redis) -> None:
    env, _ = await _tenant(broker, Scripted())
    job = await seed_job(env.t)
    _p1, (first,) = await _seed_incident(env.t, [job])
    assert await env.run(first) is AiRunStatus.COMPLETED
    _p2, (second,) = await _seed_incident(env.t, [job])
    assert await env.run(second) is AiRunStatus.COMPLETED
    assert env.provider.calls == 1
    (output,) = await _outputs(env.t, second)
    (source,) = await _outputs(env.t, first)
    assert output.body == source.body
    assert output.verification["reused_from_run_id"] == str(first)
    run = await _run_row(env.t, second)
    assert ProviderUsage.model_validate(run.usage).total == 0 and run.cost_micros == 0
    assert (await _index(env.t, second)).calls == 0
    # Citations are this run's own rows, re-verified (one verifier call per run).
    assert len(await _citations(env.t, second)) == len(await _citations(env.t, first)) > 0
    assert len(env.verifier.calls) == 2


# --- ai.resume and ai.verify -----------------------------------------------------------------


async def test_resume_resends_due_runs_once(broker: Redis) -> None:
    env, waiting = await _tenant(broker, Scripted(_error(ProviderErrorKind.TIMEOUT), None))
    assert await env.run(waiting) is AiRunStatus.WAITING
    not_due = await seed_ai_run(env.t)
    async with tenant_session(env.t.org_id, None) as s:
        await s.execute(
            update(AiRunIndex)
            .where(AiRunIndex.run_id == not_due)
            .values(dispatched_at=func.now())  # just dispatched: not stale
        )
    stale = await seed_ai_run(env.t)
    leased = await seed_ai_run(env.t)
    async with tenant_session(env.t.org_id, None) as s:
        await s.execute(
            update(AiRunIndex)
            .where(AiRunIndex.run_id.in_([stale, leased]))
            .values(dispatched_at=func.now() - timedelta(minutes=5))
        )
        await s.execute(
            update(AiRunIndex)
            .where(AiRunIndex.run_id == leased)
            .values(lease_until=func.now() + timedelta(seconds=60), lease_owner="busy")
        )
    async with tenant_session(env.t.org_id, None) as s:
        await s.execute(
            update(AiRunIndex)
            .where(AiRunIndex.run_id == waiting)
            .values(
                resume_at=func.now() - timedelta(seconds=1),
                dispatched_at=func.now() - timedelta(seconds=30),
            )
        )
    env.published.clear()
    assert await analyst.handle_resume({}, env.deps) == 2
    assert {m.run_id for m in env.published} == {waiting, stale}
    assert await analyst.handle_resume({}, env.deps) == 0  # dispatched_at bumped
    assert await analyst.handle_resume({"x": 1}, env.deps) == 0  # strict message


async def test_verify_records_the_verdict_once_per_key_version(broker: Redis) -> None:
    provider = Scripted(verify=VerifyOutcome(status=VerifyStatus.VALID))
    env, _ = await _tenant(broker, provider)
    message = {"org_id": str(env.t.org_id), "provider": "mock", "key_version": 1}
    await analyst.handle_verify(message, env.deps)
    config = await _config(env.t)
    assert (config.verify_status, config.last_error_code) == ("valid", None)
    assert config.verified_at is not None
    assert env.api_keys == [SecretStr(AI_SENTINEL_KEY)]
    await analyst.handle_verify(message, env.deps)  # deduped (same key version)
    assert provider.verifies == 1
    await analyst.handle_verify({**message, "key_version": 2}, env.deps)  # not the stored key
    assert provider.verifies == 1
    await analyst.handle_verify({"org_id": "x"}, env.deps)
    async with tenant_session(env.t.org_id, env.t.owner_id) as s:
        actions = (
            await s.scalars(
                select(AuditLog.action).where(AuditLog.target_type == "ai_provider_config")
            )
        ).all()
    assert actions == ["ai.provider_verified"]


async def test_verify_marks_an_invalid_key(broker: Redis) -> None:
    provider = Scripted(verify=VerifyOutcome(status=VerifyStatus.INVALID, error_code="auth"))
    env, _ = await _tenant(broker, provider)
    await analyst.handle_verify(
        {"org_id": str(env.t.org_id), "provider": "mock", "key_version": 1}, env.deps
    )
    config = await _config(env.t)
    assert (config.verify_status, config.last_error_code) == ("invalid", "auth")


# --- hygiene ----------------------------------------------------------------------------------


async def test_logs_and_selects_carry_no_secrets_or_content(
    broker: Redis, caplog: pytest.LogCaptureFixture
) -> None:
    statements: list[str] = []

    def record(conn: Any, cursor: Any, statement: str, *args: Any) -> None:
        statements.append(statement)

    engine = get_engine().sync_engine
    event.listen(engine, "before_cursor_execute", record)
    caplog.set_level(logging.DEBUG, logger="app")
    try:
        env, run_id = await _tenant(broker, Scripted())
        assert await env.run(run_id) is AiRunStatus.COMPLETED
        failing = await seed_ai_run(env.t)
        env.provider.steps = [_error(ProviderErrorKind.AUTH_FAILED, http_status=401)]
        assert await env.run(failing) is AiRunStatus.FAILED
        job = await seed_job(env.t)
        parent, (child,) = await _seed_incident(env.t, [job])
        env.provider.steps = [None]
        await env.run(child)
        assert await env.run(parent) is AiRunStatus.COMPLETED
    finally:
        event.remove(engine, "before_cursor_execute", record)
    logs = "\n".join(r.getMessage() for r in caplog.records if r.name.startswith("app"))
    assert logs  # the worker did log its outcomes
    canary = _canary(env.provider.requests[0])
    for secret in (AI_SENTINEL_KEY, canary, "Periodic beacon", "203.0.113.50", "INT_IP_1"):
        assert secret not in logs
    # RT26: the worker never selects the pseudonym map.
    selects = [s for s in statements if s.lstrip().upper().startswith("SELECT")]
    assert selects and not any("pseudonym_map" in s for s in selects)


# --- review fixes: reported usage, lease ownership, tree / platform re-seeding ---------------


async def test_an_error_with_reported_usage_is_settled_to_it(broker: Redis) -> None:
    err = _error(ProviderErrorKind.REFUSED, category="cyber", request_sent=True)
    err.usage = ProviderUsage(input_tokens=321, output_tokens=7)  # type: ignore[attr-defined]
    env, run_id = await _tenant(broker, Scripted(err))
    assert await env.run(run_id) is AiRunStatus.REFUSED
    run = await _run_row(env.t, run_id)
    assert ProviderUsage.model_validate(run.usage).total == 328
    assert run.metrics["usage_unknown"] is False
    assert await env.deps.budget.used_today(env.t.org_id) == 328


@pytest.mark.parametrize(
    "step",
    [
        _error(ProviderErrorKind.SPEND_LIMIT),  # -> _finish
        _error(ProviderErrorKind.TIMEOUT, request_sent=True),  # -> _wait
        None,  # -> _persist
    ],
)
async def test_a_worker_that_lost_its_lease_never_touches_the_run(
    broker: Redis, step: Step
) -> None:
    async def steal(request: ProviderRequest) -> None:
        async with tenant_session(env.t.org_id, None) as s:
            await s.execute(
                update(AiRunIndex)
                .where(AiRunIndex.run_id == run_id)
                .values(lease_until=func.now() + timedelta(seconds=60), lease_owner="other")
            )

    env, run_id = await _tenant(broker, Scripted(step, hook=steal))
    assert await env.run(run_id) is None
    run = await _run_row(env.t, run_id)
    index = await _index(env.t, run_id)
    assert (run.status, index.status, index.lease_owner) == ("running", "running", "other")
    assert await _outputs(env.t, run_id) == []


async def test_a_lost_tree_key_is_reseeded_from_the_db(broker: Redis) -> None:
    env, _ = await _tenant(broker, Scripted())
    jobs = [await seed_job(env.t), await seed_job(env.t)]
    parent, children = await _seed_incident(env.t, jobs)
    assert await env.run(children[0]) is AiRunStatus.COMPLETED
    first = ProviderUsage.model_validate((await _run_row(env.t, children[0])).usage).total
    tree_key = env.deps.budget.tree_key(parent)
    assert int(await broker.get(tree_key) or 0) == first
    await broker.delete(tree_key)  # broker restart
    assert await env.run(children[1]) is AiRunStatus.COMPLETED
    second = ProviderUsage.model_validate((await _run_row(env.t, children[1])).usage).total
    assert int(await broker.get(tree_key) or 0) == first + second


async def test_a_lost_platform_key_is_reseeded_from_the_db(broker: Redis) -> None:
    env, run_id = await _tenant(
        broker,
        Scripted(),
        config_fields={"sealed": False},
        platform_key=SecretStr("platform-dev-key-0000"),
    )
    env.deps.settings = _settings(
        env.keys,
        ai_platform_key_file="/run/secrets/ai_platform_key",
        ai_platform_provider=AiProviderName.MOCK,
        ai_platform_daily_tokens=100_000_000,
    )
    key = env.deps.budget.platform_key()
    await broker.delete(key)
    assert await env.run(run_id) is AiRunStatus.COMPLETED
    first = ProviderUsage.model_validate((await _run_row(env.t, run_id)).usage).total
    assert int(await broker.get(key) or 0) == first
    await broker.delete(key)  # broker restart
    again = await seed_ai_run(env.t)
    assert await env.run(again) is AiRunStatus.COMPLETED
    second = ProviderUsage.model_validate((await _run_row(env.t, again)).usage).total
    assert int(await broker.get(key) or 0) == first + second
    await broker.delete(key)
