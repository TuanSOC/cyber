"""The share policy (M6 phase 1, RT20): `load_policy` resolution against the database, and
its call sites in the M4 / M5 paths:

- AI preview and run creation -> `409 policy_blocked` + `reason`;
- the case-scope builder skips AI-excluded evidence (`context_stats.policy_excluded`, never
  rendered into the prompt);
- job-scope TI enrichment -> `409 policy_blocked`;
- the analyst worker fails an in-flight run `policy_blocked` with no provider call;
- the enrich worker abandons a job-scope run's items `policy_blocked` with no provider call.

Existing cases (TLP:AMBER, nothing excluded) behave as in M5.
"""

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest
import pytest_asyncio
from redis.asyncio import Redis
from sqlalchemy import select

from app.core.tenancy import tenant_session
from app.modules.ai import prompt
from app.modules.ai.context import builder
from app.modules.ai.contracts import AiErrorCode
from app.modules.analysis.models import AnalysisJob
from app.modules.evidence.models import Evidence
from app.modules.investigations import policy
from app.modules.pcap_analysis.models import Ioc
from app.modules.threat_intel import runs as ti_runs
from tests.ai_api_helpers import (
    capture_ai_sends,
    enable_ai,
    incident_builder,
    job_of,
    preview,
    request_run,
    use_fake_builder,
)
from tests.ai_doubles import make_context
from tests.case_helpers import seed_evidence, seed_job_on, set_case_policy, set_evidence_policy
from tests.factories import Registered, csrf, register
from tests.integration.seed import Tenant, seed_tenant
from tests.integration.test_analyst_worker import Scripted, _status, _tenant
from tests.integration.test_analyst_worker import broker as broker  # noqa: F401 - fixture
from tests.integration.test_enrich_worker import World, _world
from tests.ti_api_helpers import capture_sends, enrich_job, succeeded_job
from tests.ti_api_helpers import enable as enable_ti

# --- load_policy ----------------------------------------------------------------------------


async def _policy(t: Tenant, **kw: Any) -> policy.SharePolicy:
    async with tenant_session(t.org_id, t.owner_id) as s:
        return await policy.load_policy(s, t.org_id, **kw)


async def _job_evidence_and_case(
    org_id: uuid.UUID, job_id: uuid.UUID
) -> tuple[uuid.UUID, uuid.UUID]:
    async with tenant_session(org_id, None) as s:
        row = (
            await s.execute(
                select(Evidence.id, Evidence.investigation_id)
                .join(AnalysisJob, AnalysisJob.evidence_id == Evidence.id)
                .where(AnalysisJob.id == job_id)
            )
        ).one()
    return row[0], row[1]


async def test_existing_cases_allow_everything() -> None:
    t = await seed_tenant("alpha")
    evidence = await seed_evidence(t)
    job = await seed_job_on(t, evidence)
    cases: list[dict[str, Any]] = [
        {},
        {"investigation_id": t.investigation_id},
        {"job_ids": (job,)},
        {"evidence_ids": (evidence,)},
    ]
    for kw in cases:
        found = await _policy(t, **kw)
        assert (found.ai_blocked, found.ti_blocked, found.reasons) == (False, False, [])


async def test_job_resolves_to_its_evidence_and_case() -> None:
    t = await seed_tenant("alpha")
    evidence = await seed_evidence(t)
    job = await seed_job_on(t, evidence)
    await set_evidence_policy(t, evidence, ai_excluded=True)
    found = await _policy(t, job_ids=(job,))
    assert found.ai_blocked and not found.ti_blocked
    assert found.ai_reasons == [policy.EVIDENCE_AI_EXCLUDED]
    await set_case_policy(t, t.investigation_id, tlp="red")
    found = await _policy(t, job_ids=(job,))
    assert found.ai_blocked and found.ti_blocked
    assert found.ai_reason == policy.TLP_RED and found.ti_reason == policy.TLP_RED


async def test_case_scope_lists_excluded_evidence_without_blocking() -> None:
    t = await seed_tenant("alpha")
    kept = await seed_evidence(t)
    skipped = await seed_evidence(t)
    await set_evidence_policy(t, skipped, ai_excluded=True, ti_excluded=True)
    found = await _policy(t, investigation_id=t.investigation_id)
    assert not found.ai_blocked and not found.ti_blocked
    assert found.excluded_evidence_ids == frozenset({skipped})
    assert found.ti_excluded_evidence_ids == frozenset({skipped})
    assert kept not in found.excluded_evidence_ids
    await set_case_policy(t, t.investigation_id, ti_excluded=True)
    found = await _policy(t, investigation_id=t.investigation_id)
    assert found.ti_blocked and not found.ai_blocked
    assert found.ti_reason == policy.CASE_TI_EXCLUDED


async def test_other_orgs_rows_are_never_resolved() -> None:
    a = await seed_tenant("alpha")
    b = await seed_tenant("bravo")
    evidence = await seed_evidence(b)
    job = await seed_job_on(b, evidence)
    await set_case_policy(b, b.investigation_id, ai_excluded=True)
    found = await _policy(a, job_ids=(job,), evidence_ids=(evidence,))
    assert not found.ai_blocked  # RLS and the org filter: b's rows are invisible to a


# --- AI preview and run creation ------------------------------------------------------------


@pytest.mark.parametrize(
    ("setup", "reason"),
    [
        ({"case": {"ai_excluded": True}}, "case_ai_excluded"),
        ({"case": {"tlp": "red"}}, "tlp_red"),
        ({"evidence": {"ai_excluded": True}}, "evidence_ai_excluded"),
    ],
)
async def test_ai_preview_and_run_are_refused(
    monkeypatch: pytest.MonkeyPatch, setup: dict[str, dict[str, Any]], reason: str
) -> None:
    capture_ai_sends(monkeypatch)
    reg = await register(org_name="Policy AI Org")
    await enable_ai(reg.client, reg.org_id)
    job = await job_of(reg)
    # Real job ids for the incident run (its `job_digest` children have job FKs).
    use_fake_builder(monkeypatch, build=incident_builder([job]))
    evidence, case_id = await _job_evidence_and_case(reg.org_id, job)
    t = Tenant(reg.org_id, reg.user_id, case_id)
    ok = await preview(reg.client, reg.org_id, task="summarize_pcap", job_id=str(job))
    assert ok.status_code == 200, ok.text  # nothing set: as in M5
    if "case" in setup:
        await set_case_policy(t, case_id, **setup["case"])
    else:
        await set_evidence_policy(t, evidence, **setup["evidence"])
    for call in (preview, request_run):
        response = await call(reg.client, reg.org_id, task="summarize_pcap", job_id=str(job))
        assert response.status_code == 409, response.text
        assert response.json()["error"] == {
            "code": "policy_blocked",
            "message": policy.PolicyBlocked.message,
            "reason": reason,
        }
    case_run = await request_run(
        reg.client, reg.org_id, task="incident_summary", investigation_id=str(case_id)
    )
    code = case_run.json().get("error", {}).get("code") if case_run.status_code >= 400 else None
    if "evidence" in setup:
        assert code != "policy_blocked"  # skipped by the builder, not refused
    else:
        assert case_run.status_code == 409 and case_run.json()["error"]["reason"] == reason


# --- the case-scope builder -----------------------------------------------------------------


async def test_case_builder_skips_excluded_evidence() -> None:
    t = await seed_tenant("alpha")
    kept = await seed_job_on(t, await seed_evidence(t))
    excluded_evidence = await seed_evidence(t)
    excluded = await seed_job_on(t, excluded_evidence)
    await set_evidence_policy(t, excluded_evidence, ai_excluded=True)
    opts = builder.Options(
        include_ti=False,
        include_strings=False,
        include_case_text=False,
        budget_tokens=10_000,
        max_jobs=10,
    )
    async with tenant_session(t.org_id, t.owner_id) as s:
        case = await builder._case_jobs(s, t.org_id, t.investigation_id, opts)  # noqa: SLF001
    assert [j.id for j in case.jobs] == [kept]
    assert excluded not in case.scope.job_ids
    assert excluded_evidence not in case.scope.evidence_ids
    assert case.excluded == frozenset({excluded_evidence})


def test_policy_count_is_stored_but_not_rendered() -> None:
    ctx = make_context()
    counted = builder._with_policy_count(ctx, frozenset({uuid.uuid4()}))  # noqa: SLF001
    assert counted.stats.policy_excluded == 1
    assert counted.sha256 == ctx.sha256
    args = {"delimiter": "0" * 32, "canary": "c" * 24}
    assert prompt.render(counted, counted.task, **args) == prompt.render(ctx, ctx.task, **args)
    assert builder._with_policy_count(ctx, frozenset()) is ctx  # noqa: SLF001


# --- TI enrichment --------------------------------------------------------------------------


async def test_job_enrichment_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = capture_sends(monkeypatch)
    reg = await register(org_name="Policy TI Org")
    await enable_ti(reg.client, reg.org_id)
    job = await succeeded_job(reg)
    _, case_id = await _job_evidence_and_case(reg.org_id, job)
    await set_case_policy(Tenant(reg.org_id, reg.user_id, case_id), case_id, ti_excluded=True)
    response = await enrich_job(reg.client, reg.org_id, job)
    assert response.status_code == 409, response.text
    assert response.json()["error"]["reason"] == "case_ti_excluded"
    assert sent.runs == []


# --- the analyst worker re-check ------------------------------------------------------------


async def test_analyst_worker_fails_a_blocked_run_without_a_call(
    broker: Redis,  # noqa: F811
) -> None:
    provider = Scripted()
    env, run_id = await _tenant(broker, provider)
    await set_case_policy(env.t, env.t.investigation_id, ai_excluded=True)
    await env.run(run_id)
    assert await _status(env.t, run_id) == ("failed", AiErrorCode.POLICY_BLOCKED.value, "failed")
    assert provider.calls == 0


async def test_analyst_worker_runs_when_nothing_is_set(broker: Redis) -> None:  # noqa: F811
    provider = Scripted()
    env, run_id = await _tenant(broker, provider)
    await env.run(run_id)
    assert provider.calls == 1


# --- the enrich worker re-check -------------------------------------------------------------


@pytest_asyncio.fixture(loop_scope="session")
async def ti_world() -> AsyncIterator[World]:
    w = await _world()
    yield w
    await w.deps.limiter._redis.aclose()  # noqa: SLF001


async def _job_run(world: World) -> tuple[uuid.UUID, uuid.UUID]:
    t = world.t
    evidence = await seed_evidence(t)
    job = await seed_job_on(t, evidence)
    now = datetime.now(UTC)
    async with tenant_session(t.org_id, t.owner_id) as s:
        s.add(
            Ioc(
                organization_id=t.org_id,
                job_id=job,
                type="domain",
                value="hit.example.com",
                first_seen=now,
                last_seen=now,
                count=1,
                source="dns",
            )
        )
    async with tenant_session(t.org_id, t.owner_id) as s:
        created = await ti_runs.create_run(
            s, t.org_id, "job", job_id=job, providers=["mock"], requested_by=t.owner_id
        )
    assert created.run_id is not None
    return created.run_id, evidence


async def test_enrich_worker_abandons_a_blocked_run_without_a_call(ti_world: World) -> None:
    run_id, evidence = await _job_run(ti_world)
    await set_evidence_policy(ti_world.t, evidence, ti_excluded=True)
    await ti_world.slice(run_id)
    status, index_status, summary = await ti_world.state(run_id)
    assert (status, index_status) == ("failed", "failed")
    assert summary.get("ended_by") == "policy_blocked"
    items = await ti_world.items(run_id)
    assert {state for state, _, _ in items.values()} == {"abandoned"}
    assert {reason for _, reason, _ in items.values()} == {"policy_blocked"}
    assert dict(ti_world.sink.calls) == {}


async def test_enrich_worker_runs_job_scope_when_nothing_is_set(ti_world: World) -> None:
    run_id, _ = await _job_run(ti_world)
    await ti_world.slice(run_id)
    assert (await ti_world.state(run_id))[0] == "completed"
    assert dict(ti_world.sink.calls) == {"hit.example.com": 1}


async def test_manual_lookups_are_not_checked(ti_world: World) -> None:
    """Documented residual (RT20): a manual lookup has no case scope."""
    await set_case_policy(ti_world.t, ti_world.t.investigation_id, tlp="red")
    run_id = await ti_world.run("hit.example.com")
    await ti_world.slice(run_id)
    assert (await ti_world.state(run_id))[0] == "completed"


# --- InvestigationOut -----------------------------------------------------------------------


async def _new_case(reg: Registered) -> uuid.UUID:
    created = await reg.client.post(
        f"/api/v1/orgs/{reg.org_id}/investigations",
        json={"title": "Policy case", "severity": "low"},
        headers=csrf(reg.client),
    )
    assert created.status_code == 201, created.text
    body = created.json()
    assert (body["tlp"], body["share_policy"]["reasons"]) == ("amber", [])
    return uuid.UUID(body["id"])


async def test_case_is_shown_with_its_share_policy() -> None:
    reg = await register(org_name="Policy Out Org")
    case_id = await _new_case(reg)
    await set_case_policy(Tenant(reg.org_id, reg.user_id, case_id), case_id, tlp="red")
    response = await reg.client.get(f"/api/v1/orgs/{reg.org_id}/investigations/{case_id}")
    body = response.json()
    assert (body["tlp"], body["ai_excluded"], body["ti_excluded"]) == ("red", False, False)
    assert body["share_policy"] == {"ai_blocked": True, "ti_blocked": True, "reasons": ["tlp_red"]}


async def test_m6_update_fields_answer_501_until_phase_2() -> None:
    reg = await register(org_name="Policy Patch Org")
    case_id = await _new_case(reg)
    response = await reg.client.patch(
        f"/api/v1/orgs/{reg.org_id}/investigations/{case_id}",
        json={"tlp": "red"},
        headers=csrf(reg.client),
    )
    assert response.status_code == 501, response.text
    assert response.json()["error"]["code"] == "not_implemented"
