"""AI run routes (M5 phase 7): creation in one transaction, dedupe and regenerate, every
refusal (disabled, provider, job, task, rate, budget, caps under concurrency), incident
children, publish failure, preview, list, context viewer. The builder is the
`tests/ai_doubles.py` stand-in (RT12)."""

import asyncio
import uuid
from typing import Any

import pytest
from sqlalchemy import func, select

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.ai import runs, service_runs
from app.modules.ai.context import builder
from app.modules.ai.contracts import RUN_ACTIVE, AiRunRequest, ContextBuildError
from app.modules.ai.models import AiContextRef, AiRun, AiRunIndex, AiRunInput
from app.modules.ai.prompt import PROMPT_VERSION
from app.modules.ai.schemas import AiRunCreate
from app.modules.audit.models import AuditLog
from app.modules.organizations.models import MemberRole
from tests.ai_api_helpers import (
    API,
    AiSent,
    capture_ai_sends,
    enable_ai,
    finish_run,
    incident_builder,
    job_of,
    preview,
    put_provider,
    put_settings,
    request_run,
    set_usage,
    tenant_of,
    use_fake_builder,
)
from tests.ai_doubles import DEFAULT_ITEMS, make_context
from tests.ai_helpers import seed_job
from tests.factories import Registered, add_member, csrf, login, make_user, register, unique_email

_REAL_DISPATCH = runs.dispatch


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> AiSent:
    use_fake_builder(monkeypatch)
    return capture_ai_sends(monkeypatch)


async def _ready_owner() -> Registered:
    owner = await register()
    await enable_ai(owner.client, owner.org_id)
    return owner


def _seeded_strings() -> list[str]:
    """Every free-text value the fake context carries (none may reach the audit row); short
    enum-like values (`pcap`, `tcp`) are also legitimate audit words, so they are skipped."""
    return [
        v
        for _, fields in DEFAULT_ITEMS
        for v in fields.values()
        if isinstance(v, str) and (" " in v or "." in v)
    ]


async def test_run_creation_commits_everything_and_dedupes(sent: AiSent) -> None:
    owner = await _ready_owner()
    job_id = await job_of(owner)
    response = await request_run(
        owner.client, owner.org_id, task="summarize_pcap", job_id=str(job_id)
    )
    assert response.status_code == 202, response.text
    body = response.json()
    run = body["run"]
    assert body["deduplicated"] is False
    assert run["task"] == "summarize_pcap" and run["scope"] == "job"
    assert run["job_id"] == str(job_id) and run["status"] == "queued"
    assert (run["provider"], run["model"]) == ("mock", "mock-1")
    assert run["prompt_version"] == PROMPT_VERSION and run["output_schema"] == "ai.v1"
    ctx = make_context(job_id=job_id)
    assert run["context_sha256"] == ctx.sha256
    assert run["requested_by"] == str(owner.user_id) and run["children"] == 0
    run_id = uuid.UUID(run["id"])
    assert sent.runs == [run_id]

    async with tenant_session(owner.org_id, None) as s:
        index = await s.get(AiRunIndex, run_id)
        inputs = (await s.scalars(select(AiRunInput))).all()
        refs = (await s.scalars(select(AiContextRef).order_by(AiContextRef.label))).all()
        [audit] = (
            await s.scalars(select(AuditLog).where(AuditLog.action == "ai.run_requested"))
        ).all()
    assert index is not None and index.status == "queued" and index.dispatched_at is not None
    [stored] = inputs
    assert stored.stage == "base" and stored.context_sha256 == ctx.sha256
    assert stored.pseudonym_map == {"INT_IP_1": "10.0.2.20"}
    assert "pseudonym_map" not in stored.context
    assert sorted(r.label for r in refs) == sorted(r.label for r in ctx.refs)
    assert audit.target_id == run_id and audit.actor_id == owner.user_id
    details = audit.details
    assert details["task"] == "summarize_pcap" and details["provider"] == "mock"
    assert details["context_sha256"] == ctx.sha256 and details["prompt_version"] == PROMPT_VERSION
    assert details["items"]["finding"] == 2 and details["pseudonymized"] == {"ip": 1}
    assert details["inclusions"] == {
        "pseudonymize_internal": True,
        "include_strings": False,
        "include_ti": True,
        "include_case_text": False,
    }
    dump = str(details)
    for value in (*_seeded_strings(), "10.0.2.20", "INT_IP_1"):
        assert value not in dump, value

    again = await request_run(owner.client, owner.org_id, task="summarize_pcap", job_id=str(job_id))
    assert again.status_code == 200
    assert again.json()["deduplicated"] is True and again.json()["run"]["id"] == run["id"]
    assert sent.runs == [run_id]  # nothing new was published

    other_task = await request_run(
        owner.client, owner.org_id, task="ioc_correlation", job_id=str(job_id)
    )
    assert other_task.status_code == 202

    fresh = await request_run(
        owner.client, owner.org_id, task="summarize_pcap", job_id=str(job_id), regenerate=True
    )
    assert fresh.status_code == 202
    assert fresh.json()["run"]["supersedes_run_id"] == run["id"]
    assert fresh.json()["run"]["id"] != run["id"]


async def test_failed_runs_are_not_deduplicated(sent: AiSent) -> None:
    owner = await _ready_owner()
    job_id = await job_of(owner)
    first = await request_run(owner.client, owner.org_id, task="summarize_pcap", job_id=str(job_id))
    await finish_run(
        owner.org_id, first.json()["run"]["id"], status="failed", error_code="deadline"
    )
    second = await request_run(
        owner.client, owner.org_id, task="summarize_pcap", job_id=str(job_id)
    )
    assert second.status_code == 202 and second.json()["run"]["id"] != first.json()["run"]["id"]
    assert second.json()["run"]["supersedes_run_id"] is None


async def test_ai_disabled_refuses_runs_and_previews(sent: AiSent) -> None:
    owner = await register()
    job_id = await job_of(owner)
    run = await request_run(owner.client, owner.org_id, task="summarize_pcap", job_id=str(job_id))
    assert run.status_code == 409 and run.json()["error"]["code"] == "ai_disabled"
    shown = await preview(owner.client, owner.org_id, task="summarize_pcap", job_id=str(job_id))
    assert shown.status_code == 409 and shown.json()["error"]["code"] == "ai_disabled"

    await enable_ai(owner.client, owner.org_id)
    off = await put_settings(owner.client, owner.org_id, ai_enabled=False)
    assert off.status_code == 200
    again = await preview(owner.client, owner.org_id, task="summarize_pcap", job_id=str(job_id))
    assert again.json()["error"]["code"] == "ai_disabled"
    assert sent.runs == []


async def test_provider_must_be_enabled_available_and_allowed(
    sent: AiSent, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = await register()
    on = await put_settings(owner.client, owner.org_id, ai_enabled=True, acknowledge_privacy=True)
    assert on.status_code == 200
    job_id = str(await job_of(owner))
    none = await request_run(
        owner.client, owner.org_id, task="summarize_pcap", job_id=job_id, provider="mock"
    )
    assert none.status_code == 409 and none.json()["error"]["code"] == "no_provider_enabled"
    stored = await put_provider(owner.client, owner.org_id, api_key="mock-key-12345678")
    assert stored.status_code == 200
    disabled = await request_run(
        owner.client, owner.org_id, task="summarize_pcap", job_id=job_id, provider="mock"
    )
    assert disabled.json()["error"]["code"] == "no_provider_enabled"
    # Default provider (platform: anthropic) is not configured either.
    default = await request_run(owner.client, owner.org_id, task="summarize_pcap", job_id=job_id)
    assert default.json()["error"]["code"] == "no_provider_enabled"

    await put_provider(owner.client, owner.org_id, enabled=True, acknowledge_terms=True)
    model = await request_run(
        owner.client,
        owner.org_id,
        task="summarize_pcap",
        job_id=job_id,
        provider="mock",
        model="claude-sonnet-5",
    )
    assert model.status_code == 422 and model.json()["error"]["code"] == "model_not_allowed"
    gemini = await request_run(
        owner.client, owner.org_id, task="summarize_pcap", job_id=job_id, provider="gemini"
    )
    assert gemini.status_code == 422
    assert gemini.json()["error"]["code"] == "provider_unavailable"
    ok = await request_run(
        owner.client, owner.org_id, task="summarize_pcap", job_id=job_id, provider="mock"
    )
    assert ok.status_code == 202, ok.text
    monkeypatch.setattr(get_settings(), "env", "prod")
    prod = await request_run(
        owner.client, owner.org_id, task="ioc_correlation", job_id=job_id, provider="mock"
    )
    assert prod.status_code == 422 and prod.json()["error"]["code"] == "provider_unavailable"


async def test_job_task_and_target_checks(sent: AiSent, monkeypatch: pytest.MonkeyPatch) -> None:
    owner = await _ready_owner()
    tenant = await tenant_of(owner)
    queued = await seed_job(tenant, status="queued")
    static = await seed_job(tenant, "static")
    pcap = await seed_job(tenant)
    url = f"{API}/{owner.org_id}/ai/runs"
    not_ready = await request_run(
        owner.client, owner.org_id, task="summarize_pcap", job_id=str(queued)
    )
    assert not_ready.status_code == 409 and not_ready.json()["error"]["code"] == "job_not_ready"
    unknown = await request_run(
        owner.client, owner.org_id, task="summarize_pcap", job_id=str(uuid.uuid4())
    )
    assert unknown.status_code == 404
    wrong = await request_run(owner.client, owner.org_id, task="summarize_pcap", job_id=str(static))
    assert wrong.status_code == 422 and wrong.json()["error"]["code"] == "task_not_applicable"
    no_case = await request_run(
        owner.client, owner.org_id, task="incident_summary", investigation_id=str(uuid.uuid4())
    )
    assert no_case.status_code == 404
    for body in (
        {"task": "explain_finding", "job_id": str(pcap)},  # target_id missing
        {"task": "summarize_pcap", "job_id": str(pcap), "target_id": str(uuid.uuid4())},
        {"task": "job_digest", "job_id": str(pcap)},  # internal only
        {"task": "incident_summary", "job_id": str(pcap)},
        {"task": "summarize_pcap"},
        {"task": "summarize_pcap", "job_id": str(pcap), "fallback": True},
    ):
        refused = await owner.client.post(url, json=body, headers=csrf(owner.client))
        assert refused.status_code == 422, body
        assert refused.json()["error"]["code"] == "validation_error"

    async def missing(*_: Any) -> Any:
        raise ContextBuildError("target_not_found")

    monkeypatch.setattr(builder, "build_run", missing)
    target = await request_run(
        owner.client,
        owner.org_id,
        task="explain_finding",
        job_id=str(pcap),
        target_id=str(uuid.uuid4()),
    )
    assert target.status_code == 422 and target.json()["error"]["code"] == "target_not_found"

    async def empty(*_: Any) -> Any:
        raise ContextBuildError("context_empty")

    monkeypatch.setattr(builder, "build_run", empty)
    nothing = await request_run(
        owner.client, owner.org_id, task="ioc_correlation", job_id=str(pcap)
    )
    assert nothing.status_code == 422 and nothing.json()["error"]["code"] == "context_empty"
    assert sent.runs == []


async def test_per_user_rate_limit(sent: AiSent, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "ai_runs_per_user_10min", 2)
    owner = await _ready_owner()
    tenant = await tenant_of(owner)
    jobs = [await seed_job(tenant) for _ in range(3)]
    codes = [
        (
            await request_run(owner.client, owner.org_id, task="summarize_pcap", job_id=str(j))
        ).status_code
        for j in jobs
    ]
    assert codes == [202, 202, 429]


async def test_daily_budget_is_checked_against_the_db(sent: AiSent) -> None:
    owner = await _ready_owner()
    assert (
        await put_settings(owner.client, owner.org_id, daily_token_budget=1000)
    ).status_code == 200
    tenant = await tenant_of(owner)
    first_job, second_job = await seed_job(tenant), await seed_job(tenant)
    first = await request_run(
        owner.client, owner.org_id, task="summarize_pcap", job_id=str(first_job)
    )
    assert first.status_code == 202
    await set_usage(owner.org_id, first.json()["run"]["id"], 1000)
    spent = await request_run(
        owner.client, owner.org_id, task="summarize_pcap", job_id=str(second_job)
    )
    assert spent.status_code == 409 and spent.json()["error"]["code"] == "budget_exhausted"
    raised = await put_settings(owner.client, owner.org_id, daily_token_budget=5000)
    assert raised.status_code == 200
    ok = await request_run(
        owner.client, owner.org_id, task="summarize_pcap", job_id=str(second_job)
    )
    assert ok.status_code == 202


async def test_active_caps_count_children(sent: AiSent, monkeypatch: pytest.MonkeyPatch) -> None:
    owner = await _ready_owner()
    tenant = await tenant_of(owner)
    jobs = [await seed_job(tenant) for _ in range(4)]
    use_fake_builder(monkeypatch, build=incident_builder(jobs[:2]))
    monkeypatch.setattr(get_settings(), "ai_active_runs_per_org", 3)
    first = await request_run(
        owner.client, owner.org_id, task="summarize_pcap", job_id=str(jobs[2])
    )
    assert first.status_code == 202
    # An incident needs 1 + 2 slots; only 2 are free.
    incident = await request_run(
        owner.client,
        owner.org_id,
        task="incident_summary",
        investigation_id=str(tenant.investigation_id),
    )
    assert incident.status_code == 409 and incident.json()["error"]["code"] == "ai_busy"
    second = await request_run(
        owner.client, owner.org_id, task="summarize_pcap", job_id=str(jobs[3])
    )
    third = await request_run(
        owner.client, owner.org_id, task="ioc_correlation", job_id=str(jobs[3])
    )
    busy = await request_run(owner.client, owner.org_id, task="attack_mapping", job_id=str(jobs[3]))
    assert (second.status_code, third.status_code, busy.status_code) == (202, 202, 409)
    # A deduplicated request is never refused as busy.
    dedupe = await request_run(
        owner.client, owner.org_id, task="summarize_pcap", job_id=str(jobs[3])
    )
    assert dedupe.status_code == 200 and dedupe.json()["deduplicated"] is True

    other = await _ready_owner()
    other_job = await job_of(other)
    monkeypatch.setattr(get_settings(), "ai_active_runs_global", 3)
    global_busy = await request_run(
        other.client, other.org_id, task="summarize_pcap", job_id=str(other_job)
    )
    assert global_busy.status_code == 409
    assert global_busy.json()["error"]["code"] == "ai_busy"


async def test_global_cap_holds_under_concurrent_creation(
    sent: AiSent, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One free global slot, four orgs racing for it: the global advisory lock (taken after
    each org's own) serializes count + insert, so exactly one run is created."""
    owners = [await _ready_owner() for _ in range(4)]
    jobs = [await job_of(o) for o in owners]
    async with tenant_session(None, None) as session:
        active = await session.scalar(
            select(func.count()).select_from(AiRunIndex).where(AiRunIndex.status.in_(RUN_ACTIVE))
        )
    monkeypatch.setattr(get_settings(), "ai_active_runs_global", int(active or 0) + 1)
    responses = await asyncio.gather(
        *(
            request_run(o.client, o.org_id, task="summarize_pcap", job_id=str(j))
            for o, j in zip(owners, jobs, strict=True)
        )
    )
    codes = sorted(r.status_code for r in responses)
    assert codes == [202, 409, 409, 409], [r.text for r in responses]
    assert all(r.json()["error"]["code"] == "ai_busy" for r in responses if r.status_code == 409)
    assert len(sent.runs) == 1


async def test_concurrent_identical_requests_create_one_run(sent: AiSent) -> None:
    owner = await _ready_owner()
    job_id = str(await job_of(owner))
    responses = await asyncio.gather(
        *(
            request_run(owner.client, owner.org_id, task="summarize_pcap", job_id=job_id)
            for _ in range(4)
        )
    )
    assert sorted(r.status_code for r in responses) == [200, 200, 200, 202]
    assert len({r.json()["run"]["id"] for r in responses}) == 1
    assert len(sent.runs) == 1


async def test_incident_creates_children_in_one_transaction(
    sent: AiSent, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = await _ready_owner()
    tenant = await tenant_of(owner)
    jobs = [await seed_job(tenant), await seed_job(tenant, "static")]
    use_fake_builder(monkeypatch, build=incident_builder(jobs))
    response = await request_run(
        owner.client,
        owner.org_id,
        task="incident_summary",
        investigation_id=str(tenant.investigation_id),
    )
    assert response.status_code == 202, response.text
    run = response.json()["run"]
    assert run["scope"] == "investigation" and run["children"] == 2
    assert run["investigation_id"] == str(tenant.investigation_id) and run["job_id"] is None
    parent_id = uuid.UUID(run["id"])
    async with tenant_session(owner.org_id, None) as s:
        children = (await s.scalars(select(AiRun).where(AiRun.parent_run_id == parent_id))).all()
        parent = await s.get(AiRun, parent_id)
        indexed = (await s.scalars(select(AiRunIndex.run_id))).all()
        inputs = (await s.scalars(select(AiRunInput.run_id))).all()
        [audit] = (
            await s.scalars(select(AuditLog).where(AuditLog.action == "ai.run_requested"))
        ).all()
    assert parent is not None
    assert sorted(str(c.job_id) for c in children) == sorted(str(j) for j in jobs)
    assert {c.task for c in children} == {"job_digest"}
    assert {c.scope for c in children} == {"job"}
    assert all(c.deadline_at == parent.deadline_at for c in children)  # RT8
    assert all(c.requested_by == owner.user_id for c in children)
    assert set(indexed) == set(inputs) == {parent_id, *(c.id for c in children)}
    # Children are published first, then the parent.
    assert sent.runs[-1] == parent_id and set(sent.runs[:-1]) == {c.id for c in children}
    assert audit.details["children"] == 2 and audit.details["task"] == "incident_summary"

    listing = (await owner.client.get(f"{API}/{owner.org_id}/ai/runs")).json()
    assert [r["id"] for r in listing["items"]] == [run["id"]]  # top-level runs only
    detail = (await owner.client.get(f"{API}/{owner.org_id}/ai/runs/{run['id']}")).json()
    assert sorted(c["job_id"] for c in detail["child_runs"]) == sorted(str(j) for j in jobs)


async def test_publish_failure_still_answers_202(monkeypatch: pytest.MonkeyPatch) -> None:
    use_fake_builder(monkeypatch)
    capture_ai_sends(monkeypatch)
    monkeypatch.setattr(runs, "dispatch", _REAL_DISPATCH)
    published: list[Any] = []

    def broken(message: Any) -> None:
        published.append(message)
        raise ConnectionError("broker down")

    monkeypatch.setattr(runs, "_send_sync", broken)
    owner = await _ready_owner()
    job_id = await job_of(owner)
    response = await request_run(
        owner.client, owner.org_id, task="summarize_pcap", job_id=str(job_id)
    )
    assert response.status_code == 202
    run_id = uuid.UUID(response.json()["run"]["id"])
    assert [(m.run_id, m.org_id) for m in published] == [(run_id, owner.org_id)]
    async with tenant_session(owner.org_id, None) as s:
        index = await s.get(AiRunIndex, run_id)
        run = await s.get(AiRun, run_id)
    assert index is not None and run is not None
    assert (run.status, index.status) == ("queued", "queued")  # left to ai.resume
    assert index.dispatched_at is not None


async def test_preview_persists_nothing(sent: AiSent, monkeypatch: pytest.MonkeyPatch) -> None:
    owner = await _ready_owner()
    job_id = await job_of(owner)
    response = await preview(owner.client, owner.org_id, task="summarize_pcap", job_id=str(job_id))
    assert response.status_code == 200, response.text
    body = response.json()
    ctx = make_context(job_id=job_id)
    assert body["context_sha256"] == ctx.sha256 and body["provider"] == "mock"
    assert [i["label"] for i in body["items"]] == [i.label for i in ctx.items]
    assert "INT_IP_1" in response.text and "10.0.2.20" not in response.text  # never the map
    assert "finding_text" in body["categories"] and "network_flows" in body["categories"]
    assert body["inclusions"]["pseudonymize_internal"] is True
    assert body["context_stats"]["per_kind"]["finding"] == {"included": 2, "total": 2}
    async with tenant_session(owner.org_id, None) as s:
        assert await s.scalar(select(func.count(AiRun.id))) == 0
        assert (
            await s.scalar(
                select(func.count(AuditLog.id)).where(AuditLog.action.startswith("ai.run"))
            )
            == 0
        )
    assert sent.runs == []

    monkeypatch.setattr(service_runs, "PREVIEWS_PER_USER_PER_10MIN", 1)
    limited = await preview(owner.client, owner.org_id, task="summarize_pcap", job_id=str(job_id))
    assert limited.status_code == 429


async def test_viewer_reads_but_cannot_request(sent: AiSent) -> None:
    owner = await _ready_owner()
    job_id = await job_of(owner)
    created = await request_run(
        owner.client, owner.org_id, task="summarize_pcap", job_id=str(job_id)
    )
    email = unique_email("viewer")
    await add_member(owner.org_id, await make_user(email), MemberRole.VIEWER)
    viewer = await login(email)
    denied = await request_run(viewer, owner.org_id, task="ioc_correlation", job_id=str(job_id))
    assert denied.status_code == 403
    shown = await preview(viewer, owner.org_id, task="ioc_correlation", job_id=str(job_id))
    assert shown.status_code == 403
    run_id = created.json()["run"]["id"]
    assert (await viewer.get(f"{API}/{owner.org_id}/ai/runs/{run_id}")).status_code == 200


async def test_list_filters_detail_and_context(sent: AiSent) -> None:
    owner = await _ready_owner()
    tenant = await tenant_of(owner)
    job_a, job_b = await seed_job(tenant), await seed_job(tenant)
    a = (
        await request_run(owner.client, owner.org_id, task="summarize_pcap", job_id=str(job_a))
    ).json()
    b = (
        await request_run(owner.client, owner.org_id, task="ioc_correlation", job_id=str(job_b))
    ).json()
    base = f"{API}/{owner.org_id}/ai/runs"
    everything = (await owner.client.get(base)).json()
    assert everything["total"] == 2
    assert [r["id"] for r in everything["items"]] == [b["run"]["id"], a["run"]["id"]]
    by_job = (await owner.client.get(base, params={"job_id": str(job_a)})).json()
    assert [r["id"] for r in by_job["items"]] == [a["run"]["id"]]
    by_task = (await owner.client.get(base, params={"task": "ioc_correlation"})).json()
    assert [r["id"] for r in by_task["items"]] == [b["run"]["id"]]
    by_status = (await owner.client.get(base, params={"status": "completed"})).json()
    assert by_status["total"] == 0
    paged = (await owner.client.get(base, params={"limit": 1, "offset": 1})).json()
    assert [r["id"] for r in paged["items"]] == [a["run"]["id"]] and paged["total"] == 2
    bad = await owner.client.get(base, params={"status": "exploded"})
    assert bad.status_code == 422

    detail = (await owner.client.get(f"{base}/{a['run']['id']}")).json()
    assert detail["status"] == "queued" and detail["output"] is None
    assert detail["output_withheld"] is False and detail["context_stats"]["truncated"] is False
    missing = await owner.client.get(f"{base}/{uuid.uuid4()}")
    assert missing.status_code == 404

    context = await owner.client.get(f"{base}/{a['run']['id']}/context")
    assert context.status_code == 200
    body = context.json()
    ctx = make_context(job_id=job_a)
    assert body["context_sha256"] == ctx.sha256 and body["revealed"] is False
    [stage] = body["stages"]
    assert stage["stage"] == "base" and stage["pseudonym_map"] is None
    assert stage["items"][1]["fields"]["title"].startswith("Periodic beacon from INT_IP_1")
    assert "10.0.2.20" not in context.text and "ref_id" not in context.text
    revealed = (
        await owner.client.get(f"{base}/{a['run']['id']}/context", params={"reveal": True})
    ).json()
    assert revealed["revealed"] is True
    assert revealed["stages"][0]["pseudonym_map"] == {"INT_IP_1": "10.0.2.20"}


async def test_request_body_reuses_the_frozen_contract() -> None:
    """The route body is the frozen `AiRunRequest` (with `regenerate` optional)."""
    assert issubclass(AiRunCreate, AiRunRequest)
    schema = AiRunCreate.model_json_schema()
    assert "default" not in schema["properties"]["regenerate"]


async def test_revealing_the_pseudonym_map_is_audited(sent: AiSent) -> None:
    owner = await _ready_owner()
    job_id = await job_of(owner)
    created = await request_run(
        owner.client, owner.org_id, task="summarize_pcap", job_id=str(job_id)
    )
    run_id = created.json()["run"]["id"]
    url = f"{API}/{owner.org_id}/ai/runs/{run_id}/context"
    assert (await owner.client.get(url)).status_code == 200
    viewer_email = unique_email("viewer")
    await add_member(owner.org_id, await make_user(viewer_email), MemberRole.VIEWER)
    viewer = await login(viewer_email)
    revealed = await viewer.get(url, params={"reveal": True})
    assert revealed.status_code == 200
    async with tenant_session(owner.org_id, None) as s:
        rows = (
            await s.scalars(select(AuditLog).where(AuditLog.action == "ai.context_revealed"))
        ).all()
    [row] = rows  # the plain read is not audited, the reveal is
    assert row.target_id == uuid.UUID(run_id) and row.target_type == "ai_run"
    assert row.actor_id != owner.user_id and row.details == {"stages": ["base"]}
    assert "10.0.2.20" not in str(row.details) and "INT_IP" not in str(row.details)
