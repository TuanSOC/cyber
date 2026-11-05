"""The case-wide IOC read (M6 phase 2, RT11): `GET /investigations/{id}/iocs` and
`ioc_collections.case_iocs.case_iocs` (also called by the phase-3 snapshot builder).

Dedupe across jobs, the latest succeeded job per evidence (and analyzer) only, other cases'
IOCs absent, filters, paging and the collections holding each IOC."""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from httpx import AsyncClient

from app.core.tenancy import tenant_session
from app.modules.ioc_collections.case_iocs import case_iocs
from app.modules.pcap_analysis.models import Ioc
from tests.case_helpers import seed_case, seed_evidence, seed_job_on
from tests.factories import Registered, register
from tests.integration.seed import Tenant
from tests.integration.test_case_ioc_collections import add, new_collection
from tests.integration.test_case_status import API
from tests.ti_api_helpers import key_of

T0 = datetime(2026, 3, 1, tzinfo=UTC)


async def seed_iocs(t: Tenant, job_id: uuid.UUID, *rows: tuple[str, str, int, int]) -> None:
    """(type, value, first-seen offset s, last-seen offset s) rows of a job."""
    async with tenant_session(t.org_id, t.owner_id) as s:
        for ioc_type, value, first, last in rows:
            s.add(
                Ioc(
                    organization_id=t.org_id,
                    job_id=job_id,
                    type=ioc_type,
                    value=value,
                    first_seen=T0 + timedelta(seconds=first),
                    last_seen=T0 + timedelta(seconds=last),
                    count=1,
                    source="dns",
                )
            )


async def _tenant(reg: Registered) -> Tenant:
    t = Tenant(reg.org_id, reg.user_id, uuid.uuid4())
    case_id = await seed_case(t)
    return Tenant(reg.org_id, reg.user_id, case_id)


async def read(client: AsyncClient, org_id: uuid.UUID, case_id: uuid.UUID, **params: Any) -> Any:
    response = await client.get(f"{API}/{org_id}/investigations/{case_id}/iocs", params=params)
    assert response.status_code == 200, response.text
    return response.json()


async def test_dedupe_across_jobs_and_latest_job_per_evidence_only() -> None:
    reg = await register()
    t = await _tenant(reg)
    first_evidence = await seed_evidence(t, t.investigation_id)
    old_job = await seed_job_on(t, first_evidence)
    new_job = await seed_job_on(t, first_evidence)  # the latest succeeded pcap job
    queued = await seed_job_on(t, first_evidence, status="queued")  # newest, not succeeded
    static_job = await seed_job_on(t, first_evidence, "static")  # newer, other analyzer
    second_evidence = await seed_evidence(t, t.investigation_id)
    second_job = await seed_job_on(t, second_evidence)
    await seed_iocs(t, old_job, ("domain", "stale.com", 0, 1))
    await seed_iocs(t, new_job, ("domain", "evil.com", 10, 20), ("ip", "203.0.113.7", 0, 5))
    await seed_iocs(t, queued, ("domain", "queued.com", 0, 1))
    await seed_iocs(t, static_job, ("file_sha256", "A" * 64, 0, 0))
    await seed_iocs(t, second_job, ("domain", "evil.com", 5, 50))
    # Another case of the same org, with the same and other values.
    other = Tenant(reg.org_id, reg.user_id, await seed_case(t, title="Other case"))
    other_job = await seed_job_on(other, await seed_evidence(other, other.investigation_id))
    await seed_iocs(other, other_job, ("domain", "evil.com", 0, 1), ("domain", "other.com", 0, 1))

    page = await read(reg.client, reg.org_id, t.investigation_id)
    by_value = {i["value"]: i for i in page["items"]}
    assert set(by_value) == {"evil.com", "203.0.113.7", "A" * 64}
    evil = by_value["evil.com"]
    assert evil["count_jobs"] == 2
    assert sorted(evil["job_ids"]) == sorted([str(new_job), str(second_job)])
    assert evil["first_seen"].startswith("2026-03-01T00:00:05")
    assert evil["last_seen"].startswith("2026-03-01T00:00:50")
    assert (evil["ioc_type"], evil["ioc_key"]) == ("domain", key_of("domain", "evil.com"))
    assert by_value["203.0.113.7"]["ioc_type"] == "ipv4"
    assert by_value["A" * 64]["ioc_key"] == key_of("sha256", "a" * 64)
    assert page["items"][0]["value"] == "evil.com"  # most jobs first
    assert page["total"] == 3 and page["next_cursor"] is None


async def test_filters_paging_and_collections() -> None:
    reg = await register()
    t = await _tenant(reg)
    job = await seed_job_on(t, await seed_evidence(t, t.investigation_id))
    await seed_iocs(
        t,
        job,
        *((("domain", f"d{i:02d}.com", 0, 1)) for i in range(7)),
        ("ip", "198.51.100.4", 0, 1),
        ("ja3", "771,1,2", 0, 1),
    )
    assert [
        i["value"]
        for i in (await read(reg.client, reg.org_id, t.investigation_id, type="ipv4"))["items"]
    ] == ["198.51.100.4"]
    assert [
        i["value"]
        for i in (await read(reg.client, reg.org_id, t.investigation_id, type="ip"))["items"]
    ] == ["198.51.100.4"]
    assert [
        i["value"]
        for i in (await read(reg.client, reg.org_id, t.investigation_id, q="d03"))["items"]
    ] == ["d03.com"]
    ja3 = (await read(reg.client, reg.org_id, t.investigation_id, type="ja3"))["items"]
    assert [(i["ioc_type"], i["value"]) for i in ja3] == [("ja3", "771,1,2")]

    first = await read(reg.client, reg.org_id, t.investigation_id, limit=4)
    assert len(first["items"]) == 4 and first["next_cursor"] and first["total"] == 9
    second = await read(
        reg.client, reg.org_id, t.investigation_id, limit=4, cursor=first["next_cursor"]
    )
    third = await read(
        reg.client, reg.org_id, t.investigation_id, limit=4, cursor=second["next_cursor"]
    )
    values = [i["value"] for i in first["items"] + second["items"] + third["items"]]
    assert len(values) == len(set(values)) == 9
    assert third["next_cursor"] is None

    collection = (await new_collection(reg.client, reg.org_id, str(t.investigation_id))).json()
    await add(reg.client, reg.org_id, collection["id"], {"type": "domain", "value": "D01.com"})
    page = await read(reg.client, reg.org_id, t.investigation_id, q="d01")
    assert page["items"][0]["in_collections"] == [collection["id"]]
    assert (await read(reg.client, reg.org_id, t.investigation_id, q="d02"))["items"][0][
        "in_collections"
    ] == []


async def test_entry_point_matches_the_route_and_is_tenant_scoped() -> None:
    reg = await register()
    other = await register()
    t = await _tenant(reg)
    job = await seed_job_on(t, await seed_evidence(t, t.investigation_id))
    await seed_iocs(t, job, ("domain", "evil.com", 0, 1))
    async with tenant_session(reg.org_id, reg.user_id) as s:
        direct = await case_iocs(s, reg.org_id, t.investigation_id, limit=10)
    route = await read(reg.client, reg.org_id, t.investigation_id, limit=10)
    assert direct.model_dump(mode="json") == route
    # Another org: its session sees nothing of this case; the route is 404.
    async with tenant_session(other.org_id, other.user_id) as s:
        foreign = await case_iocs(s, other.org_id, t.investigation_id, limit=10)
    assert foreign.items == [] and foreign.total == 0
    for org_id in (reg.org_id, other.org_id):
        response = await other.client.get(
            f"{API}/{org_id}/investigations/{t.investigation_id}/iocs"
        )
        assert response.status_code == 404
    bad = await reg.client.get(
        f"{API}/{reg.org_id}/investigations/{t.investigation_id}/iocs", params={"cursor": "!!"}
    )
    assert bad.status_code == 400
    too_many = await reg.client.get(
        f"{API}/{reg.org_id}/investigations/{t.investigation_id}/iocs", params={"limit": 501}
    )
    assert too_many.status_code == 422


async def test_empty_case() -> None:
    reg = await register()
    t = await _tenant(reg)
    assert await read(reg.client, reg.org_id, t.investigation_id) == {
        "items": [],
        "next_cursor": None,
        "total": 0,
    }
