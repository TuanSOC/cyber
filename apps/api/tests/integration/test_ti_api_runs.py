"""Enrichment run routes (M4 phase 5): job runs and manual lookups, dedupe, caps, rate
limits, publish failure, run reads. Publishing is captured (no live enrich worker)."""

import asyncio
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.audit.models import AuditLog
from app.modules.organizations.models import MemberRole
from app.modules.threat_intel import runs, service_runs
from app.modules.threat_intel.models import RUN_ACTIVE, TiEnrichmentRun, TiRunIndex, TiRunItem
from tests.factories import Registered, add_member, login, make_user, register, unique_email
from tests.ti_api_helpers import (
    API,
    Sent,
    capture_sends,
    enable,
    enrich_job,
    key_of,
    lookup,
    queued_job,
    succeeded_job,
)

_REAL_DISPATCH = runs.dispatch


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> Sent:
    return capture_sends(monkeypatch)


async def _owner_with_mock() -> Registered:
    owner = await register()
    await enable(owner.client, owner.org_id)
    return owner


async def _member(owner: Registered, role: MemberRole) -> AsyncClient:
    email = unique_email(role.value)
    await add_member(owner.org_id, await make_user(email), role)
    return await login(email)


async def test_job_enrichment_creates_one_run_and_dedupes(sent: Sent) -> None:
    owner = await _owner_with_mock()
    job_id = await succeeded_job(owner)

    first = await enrich_job(owner.client, owner.org_id, job_id)
    assert first.status_code == 202, first.text
    body = first.json()
    run = body["run"]
    assert body["deduplicated"] is False and body["report"] == []
    assert run["scope"] == "job" and run["job_id"] == str(job_id)
    assert run["status"] == "queued" and run["providers"] == ["mock"]
    assert run["requested_by"] == str(owner.user_id) and run["deadline_at"]
    # IOCs: example.com (the mock's special-use exemption) is planned, 192.0.2.1 is not.
    assert body["items"] == 1 and body["summary"]["skipped"] == {"not_global_ip": 1}
    assert sent.runs == [(uuid.UUID(run["id"]), owner.org_id)]

    again = await enrich_job(owner.client, owner.org_id, job_id, providers=["mock"])
    assert again.status_code == 200
    assert again.json()["deduplicated"] is True and again.json()["run"]["id"] == run["id"]
    assert len(sent.runs) == 1  # nothing new was published

    async with tenant_session(owner.org_id, None) as s:
        runs_ = (await s.scalars(select(TiEnrichmentRun))).all()
        items = (await s.scalars(select(TiRunItem))).all()
        audits = (
            await s.scalars(select(AuditLog).where(AuditLog.action == "ti.enrichment_requested"))
        ).all()
    assert len(runs_) == 1
    assert [(i.provider, i.ioc_type, i.value_norm) for i in items] == [
        ("mock", "domain", "example.com")
    ]
    [audit] = audits
    assert audit.target_id == uuid.UUID(run["id"]) and audit.actor_id == owner.user_id
    assert audit.details["scope"] == "job" and audit.details["job_id"] == str(job_id)
    assert audit.details["providers"] == ["mock"] and audit.details["items"] == 1
    assert "example.com" not in str(audit.details) and "192.0.2.1" not in str(audit.details)


async def test_job_must_be_succeeded_and_in_the_org(sent: Sent) -> None:
    owner = await _owner_with_mock()
    queued = await queued_job(owner)
    not_ready = await enrich_job(owner.client, owner.org_id, queued)
    assert not_ready.status_code == 409
    assert not_ready.json()["error"]["code"] == "job_not_ready"
    unknown = await enrich_job(owner.client, owner.org_id, uuid.uuid4())
    assert unknown.status_code == 404
    assert sent.runs == []


async def test_provider_must_be_enabled(sent: Sent) -> None:
    owner = await register()
    none = await lookup(owner.client, owner.org_id, "hit.example.com")
    assert none.status_code == 409 and none.json()["error"]["code"] == "no_provider_enabled"
    await enable(owner.client, owner.org_id)
    vt = await lookup(owner.client, owner.org_id, "8.8.8.8", providers=["virustotal"])
    assert vt.status_code == 409 and vt.json()["error"]["code"] == "provider_not_enabled"
    unknown = await lookup(owner.client, owner.org_id, "8.8.8.8", providers=["shodan"])
    assert unknown.status_code == 422
    assert sent.runs == []


async def test_lookup_reports_every_value(sent: Sent) -> None:
    owner = await _owner_with_mock()
    response = await lookup(
        owner.client,
        owner.org_id,
        "hit.example.com",
        "10.0.0.1",
        "hxxps://hit-url.example.com/reset?token=s3cr3t",
        {"value": "5.1.168.192.in-addr.arpa", "type": "domain"},
        {"value": "registry", "type": "sha256"},
    )
    assert response.status_code == 202, response.text
    body = response.json()
    report = body["report"]
    assert [r["index"] for r in report] == [0, 1, 2, 3, 4]
    assert report[0]["ioc_type"] == "domain" and report[0]["providers"] == ["mock"]
    assert report[0]["ioc_key"] == key_of("domain", "hit.example.com")
    assert report[1]["skipped"] == "not_global_ip" and report[1]["providers"] == []
    assert report[2]["value_norm"] == "https://hit-url.example.com/reset"
    assert set(report[2]["notes"]) == {"query_removed", "refanged"}
    assert report[3]["skipped"] == "special_use_name"
    assert report[4]["skipped"] == "invalid"
    assert body["items"] == 2 and body["run"]["scope"] == "manual"
    run_id = uuid.UUID(body["run"]["id"])
    assert sent.runs == [(run_id, owner.org_id)]
    async with tenant_session(owner.org_id, None) as s:
        planned = (await s.scalars(select(TiRunItem.value_norm).order_by(TiRunItem.seq))).all()
    assert planned == ["hit.example.com", "https://hit-url.example.com/reset"]
    assert "s3cr3t" not in response.text  # the query string is neither planned nor echoed


async def test_nothing_eligible_answers_200_with_the_report_only(sent: Sent) -> None:
    owner = await _owner_with_mock()
    response = await lookup(owner.client, owner.org_id, "10.0.0.1", "printer.local")
    assert response.status_code == 200
    body = response.json()
    assert body["run"] is None and body["items"] == 0 and body["deduplicated"] is False
    assert [r["skipped"] for r in body["report"]] == ["not_global_ip", "special_use_name"]
    assert sent.runs == []
    async with tenant_session(owner.org_id, None) as s:
        assert (await s.scalars(select(TiEnrichmentRun))).first() is None


async def test_value_count_and_size_limits(sent: Sent) -> None:
    owner = await _owner_with_mock()
    too_many = await lookup(owner.client, owner.org_id, *[f"h{i}.example.com" for i in range(21)])
    assert too_many.status_code == 422
    assert too_many.json()["error"]["code"] == "too_many_values"
    too_long = await lookup(owner.client, owner.org_id, "a" * 2049)
    assert too_long.status_code == 422
    empty = await lookup(owner.client, owner.org_id)
    assert empty.status_code == 422


async def test_enrichment_busy_per_org_and_global(
    sent: Sent, monkeypatch: pytest.MonkeyPatch
) -> None:
    owner = await _owner_with_mock()
    for i in range(service_runs.MAX_ACTIVE_RUNS_PER_ORG):
        ok = await lookup(owner.client, owner.org_id, f"hit{i}.example.com")
        assert ok.status_code == 202
    busy = await lookup(owner.client, owner.org_id, "hit9.example.com")
    assert busy.status_code == 409 and busy.json()["error"]["code"] == "enrichment_busy"

    other = await _owner_with_mock()
    monkeypatch.setattr(service_runs, "MAX_ACTIVE_RUNS_GLOBAL", 3)
    global_busy = await lookup(other.client, other.org_id, "hit.example.com")
    assert global_busy.status_code == 409
    assert global_busy.json()["error"]["code"] == "enrichment_busy"
    assert len(sent.runs) == service_runs.MAX_ACTIVE_RUNS_PER_ORG


async def test_global_cap_holds_under_concurrent_creation(
    sent: Sent, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One free global slot, four orgs racing for it: the global advisory lock (taken after
    each org's own) serializes count + insert, so exactly one run is created."""
    owners = [await _owner_with_mock() for _ in range(4)]
    async with tenant_session(None, None) as session:
        active = await session.scalar(
            select(func.count()).select_from(TiRunIndex).where(TiRunIndex.status.in_(RUN_ACTIVE))
        )
    monkeypatch.setattr(service_runs, "MAX_ACTIVE_RUNS_GLOBAL", int(active or 0) + 1)
    responses = await asyncio.gather(
        *(lookup(o.client, o.org_id, f"race{i}.example.com") for i, o in enumerate(owners))
    )
    codes = sorted(r.status_code for r in responses)
    assert codes == [202, 409, 409, 409], [r.text for r in responses]
    assert all(
        r.json()["error"]["code"] == "enrichment_busy" for r in responses if r.status_code == 409
    )
    assert len(sent.runs) == 1


async def test_per_user_rate_limit(sent: Sent, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(service_runs, "RUNS_PER_USER_PER_10MIN", 2)
    owner = await _owner_with_mock()
    codes = [
        (await lookup(owner.client, owner.org_id, f"hit{i}.example.com")).status_code
        for i in range(3)
    ]
    assert codes == [202, 202, 429]


async def test_publish_failure_still_answers_202(monkeypatch: pytest.MonkeyPatch) -> None:
    capture_sends(monkeypatch)
    monkeypatch.setattr(runs, "dispatch", _REAL_DISPATCH)

    def broken(_: object) -> None:
        raise ConnectionError("broker down")

    monkeypatch.setattr(runs, "_send_sync", broken)
    owner = await _owner_with_mock()
    response = await lookup(owner.client, owner.org_id, "hit.example.com")
    assert response.status_code == 202
    run_id = uuid.UUID(response.json()["run"]["id"])
    async with tenant_session(owner.org_id, None) as s:
        index = await s.get(TiRunIndex, run_id)
        run = await s.get(TiEnrichmentRun, run_id)
    assert index is not None and run is not None
    # Left to ti.resume: still queued, with its dispatch time recorded.
    assert (run.status, index.status) == ("queued", "queued")
    assert index.dispatched_at is not None


async def test_viewer_cannot_request_but_can_read(sent: Sent) -> None:
    owner = await _owner_with_mock()
    job_id = await succeeded_job(owner)
    viewer = await _member(owner, MemberRole.VIEWER)
    analyst = await _member(owner, MemberRole.ANALYST)
    assert (await lookup(viewer, owner.org_id, "hit.example.com")).status_code == 403
    assert (await enrich_job(viewer, owner.org_id, job_id)).status_code == 403
    created = await lookup(analyst, owner.org_id, "hit.example.com")
    assert created.status_code == 202
    listed = await viewer.get(f"{API}/{owner.org_id}/ti/runs")
    assert listed.status_code == 200 and listed.json()["total"] == 1


async def test_provider_unavailable_in_prod(sent: Sent, monkeypatch: pytest.MonkeyPatch) -> None:
    owner = await _owner_with_mock()
    monkeypatch.setattr(get_settings(), "env", "prod")
    explicit = await lookup(owner.client, owner.org_id, "hit.example.com", providers=["mock"])
    assert explicit.status_code == 422
    assert explicit.json()["error"]["code"] == "provider_unavailable"
    default = await lookup(owner.client, owner.org_id, "hit.example.com")
    assert default.status_code == 409
    assert default.json()["error"]["code"] == "no_provider_enabled"
    assert sent.runs == []


async def test_run_list_and_detail(sent: Sent) -> None:
    owner = await _owner_with_mock()
    job_id = await succeeded_job(owner)
    job_run = (await enrich_job(owner.client, owner.org_id, job_id)).json()["run"]
    manual = (await lookup(owner.client, owner.org_id, "hit.example.com", "8.8.8.8")).json()

    base = f"{API}/{owner.org_id}/ti/runs"
    listed = (await owner.client.get(base)).json()
    assert listed["total"] == 2
    assert [r["id"] for r in listed["items"]] == [manual["run"]["id"], job_run["id"]]
    by_job = (await owner.client.get(base, params={"job_id": str(job_id)})).json()
    assert [r["id"] for r in by_job["items"]] == [job_run["id"]]
    assert (await owner.client.get(base, params={"status": "completed"})).json()["total"] == 0
    assert (await owner.client.get(base, params={"status": "queued"})).json()["total"] == 2
    assert (await owner.client.get(base, params={"status": "bogus"})).status_code == 422

    detail = (await owner.client.get(f"{base}/{manual['run']['id']}")).json()
    assert detail["status"] == "queued" and detail["resume_at"] is None
    assert detail["requested_by_name"]
    items = detail["items"]
    assert items["total"] == 2
    assert [(i["seq"], i["value_norm"], i["state"]) for i in items["items"]] == [
        (0, "hit.example.com", "pending"),
        (1, "8.8.8.8", "pending"),
    ]
    assert all(i["result"] is None and i["from_cache"] is False for i in items["items"])
    paged = (
        await owner.client.get(f"{base}/{manual['run']['id']}", params={"limit": 1, "offset": 1})
    ).json()
    assert [i["seq"] for i in paged["items"]["items"]] == [1]
    filtered = (
        await owner.client.get(
            f"{base}/{manual['run']['id']}", params={"state": "done", "provider": "mock"}
        )
    ).json()
    assert filtered["items"]["total"] == 0
    assert (await owner.client.get(f"{base}/{uuid.uuid4()}")).status_code == 404
