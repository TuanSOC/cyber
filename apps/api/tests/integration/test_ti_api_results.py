"""Result routes (M4 phase 5): `include=enrichment` on the IOC list, history per indicator,
single results, cached items in run details, and tenant isolation of all of it."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.core.tenancy import tenant_session
from tests.factories import Registered, csrf, register
from tests.ti_api_helpers import (
    API,
    Sent,
    add_result,
    capture_sends,
    enable,
    enrich_job,
    key_of,
    lookup,
    mark_cached,
    succeeded_job,
)

VT_SUMMARY = {
    "provider": "virustotal",
    "last_analysis_stats": {"malicious": 2, "suspicious": 0, "harmless": 60, "undetected": 9},
    "reputation": -3,
    "tags": ["test"],
}


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> Sent:
    return capture_sends(monkeypatch)


async def _owner() -> Registered:
    owner = await register()
    await enable(owner.client, owner.org_id)
    return owner


async def _run(owner: Registered, *values: str) -> str:
    response = await lookup(owner.client, owner.org_id, *values)
    assert response.status_code == 202, response.text
    return str(response.json()["run"]["id"])


async def test_ioc_list_include_enrichment(sent: Sent) -> None:
    owner = await _owner()
    job_id = await succeeded_job(owner)
    run = (await enrich_job(owner.client, owner.org_id, job_id)).json()["run"]["id"]
    old = datetime.now(UTC) - timedelta(hours=2)
    ok = await add_result(
        owner.org_id, run, value_norm="example.com", fetched_at=old, expires_in=timedelta(days=1)
    )
    # A later error of the same provider does not hide its earlier answer.
    later = await _run(owner, "hit.example.com")
    await add_result(
        owner.org_id, later, value_norm="example.com", status="error", complete_item=False
    )
    vt = await add_result(
        owner.org_id,
        later,
        provider="virustotal",
        value_norm="example.com",
        summary=VT_SUMMARY,
        expires_in=None,  # already expired: stale
        complete_item=False,
    )

    url = f"{API}/{owner.org_id}/analyses/{job_id}/iocs"
    plain = (await owner.client.get(url)).json()
    assert all(i["enrichment"] is None and i["enrichment_skip"] is None for i in plain["items"])

    body = (await owner.client.get(url, params={"include": "enrichment"})).json()
    rows = {i["value"]: i for i in body["items"]}
    assert body["total"] == 2
    ip = rows["192.0.2.1"]
    assert ip["enrichment"] == [] and ip["enrichment_skip"] == "not_global_ip"
    domain = rows["example.com"]
    assert domain["enrichment_skip"] == "special_use_name"  # only the dev/test mock takes it
    by_provider = {e["provider"]: e for e in domain["enrichment"]}
    assert set(by_provider) == {"mock", "virustotal"}
    mock = by_provider["mock"]
    assert mock["result_id"] == str(ok) and mock["status"] == "ok" and mock["found"] is True
    assert mock["stale"] is False and mock["permalink"] == "https://ti-mock.example/x"
    assert mock["tags"] == ["mock"] and mock["score"] == 3.0
    assert by_provider["virustotal"]["result_id"] == str(vt)
    assert by_provider["virustotal"]["stale"] is True
    assert (await owner.client.get(url, params={"include": "bogus"})).status_code == 422


async def test_history_lists_every_answer_newest_first(sent: Sent) -> None:
    owner = await _owner()
    first = await _run(owner, "hit.example.com")
    second = await _run(owner, "hit.example.com", "8.8.8.8")
    t0 = datetime.now(UTC) - timedelta(hours=3)
    a = await add_result(owner.org_id, first, fetched_at=t0)
    b = await add_result(
        owner.org_id, second, status="not_found", fetched_at=t0 + timedelta(hours=1)
    )
    c = await add_result(
        owner.org_id,
        second,
        provider="virustotal",
        summary={**VT_SUMMARY, "tags": ["x"]},
        complete_item=False,
    )
    await add_result(owner.org_id, second, ioc_type="ipv4", value_norm="8.8.8.8")

    url = f"{API}/{owner.org_id}/ti/results"
    body = (await owner.client.get(url, params={"value": "HIT.example.COM."})).json()
    assert body["ioc_type"] == "domain" and body["value_norm"] == "hit.example.com"
    assert body["ioc_key"] == key_of("domain", "hit.example.com")
    assert body["skipped"] == "special_use_name" and body["total"] == 3
    assert [i["id"] for i in body["items"]] == [str(c), str(b), str(a)]
    vt = body["items"][0]
    assert vt["summary"]["provider"] == "virustotal"
    assert vt["summary"]["last_analysis_stats"]["malicious"] == 2
    assert body["items"][1]["status"] == "not_found"
    assert body["items"][2]["summary"] == {
        "provider": "mock",
        "behaviour": None,
        "label": "test-hit",
        "hits": 3,
        "tags": [],
    }
    only_mock = (
        await owner.client.get(url, params={"value": "hit.example.com", "provider": "mock"})
    ).json()
    assert only_mock["total"] == 2
    paged = (
        await owner.client.get(url, params={"value": "hit.example.com", "limit": 1, "offset": 1})
    ).json()
    assert [i["id"] for i in paged["items"]] == [str(b)] and paged["total"] == 3

    ip = (await owner.client.get(url, params={"value": "8.8.8.8", "type": "ipv4"})).json()
    assert ip["skipped"] is None and ip["total"] == 1
    private = (await owner.client.get(url, params={"value": "10.0.0.1"})).json()
    assert private["skipped"] == "not_global_ip" and private["items"] == []
    url_query = (
        await owner.client.get(url, params={"value": "https://acme-corp.net/a?token=1"})
    ).json()
    assert url_query["notes"] == ["query_removed"]
    assert url_query["value_norm"] == "https://acme-corp.net/a"
    for bad in ({"value": "not a domain!!"}, {"value": "xyz", "type": "sha256"}):
        invalid = await owner.client.get(url, params=bad)
        assert invalid.status_code == 400 and invalid.json()["error"]["code"] == "invalid_ioc"
    assert (await owner.client.get(url)).status_code == 422  # value is required


async def test_single_result(sent: Sent) -> None:
    owner = await _owner()
    run = await _run(owner, "hit.example.com")
    result_id = await add_result(owner.org_id, run, provider="virustotal", summary=VT_SUMMARY)
    body = (await owner.client.get(f"{API}/{owner.org_id}/ti/results/{result_id}")).json()
    assert body["id"] == str(result_id) and body["run_id"] == run
    assert body["provider"] == "virustotal" and body["summary"]["reputation"] == -3
    assert body["fetched_at"] and body["expires_at"] and body["stale"] is False
    missing = await owner.client.get(f"{API}/{owner.org_id}/ti/results/{uuid.uuid4()}")
    assert missing.status_code == 404


async def test_run_detail_shows_cached_items(sent: Sent) -> None:
    owner = await _owner()
    first = await _run(owner, "hit.example.com")
    result_id = await add_result(owner.org_id, first)
    second = await _run(owner, "hit.example.com")
    await mark_cached(owner.org_id, second, result_id)

    base = f"{API}/{owner.org_id}/ti/runs"
    done = (await owner.client.get(f"{base}/{first}")).json()["items"]["items"]
    assert done[0]["state"] == "done" and done[0]["from_cache"] is False
    assert done[0]["result"]["id"] == str(result_id)
    cached = (await owner.client.get(f"{base}/{second}")).json()["items"]["items"]
    assert cached[0]["state"] == "cached" and cached[0]["from_cache"] is True
    assert cached[0]["result"]["id"] == str(result_id)
    assert cached[0]["result"]["summary"]["label"] == "test-hit"
    by_state = (await owner.client.get(f"{base}/{second}", params={"state": "cached"})).json()
    assert by_state["items"]["total"] == 1


async def test_another_org_sees_nothing(sent: Sent) -> None:
    victim = await _owner()
    job_id = await succeeded_job(victim)
    run = (await enrich_job(victim.client, victim.org_id, job_id)).json()["run"]["id"]
    result_id = await add_result(victim.org_id, run, value_norm="example.com")
    lookup_run = await _run(victim, "hit.example.com")
    await add_result(victim.org_id, lookup_run)
    await victim.client.put(
        f"{API}/{victim.org_id}/ti/settings",
        json={"excluded_suffixes": ["victim-corp.net"]},
        headers=csrf(victim.client),
    )

    attacker = await register(org_name="Attacker Org")
    a = attacker.client
    own = f"{API}/{attacker.org_id}"
    foreign = f"{API}/{victim.org_id}"
    # Foreign org paths: 404 (membership), never data.
    for path in (
        "/integrations",
        "/ti/settings",
        "/ti/runs",
        f"/ti/runs/{run}",
        f"/ti/results/{result_id}",
        f"/analyses/{job_id}/iocs?include=enrichment",
    ):
        assert (await a.get(f"{foreign}{path}")).status_code == 404, path
    history = await a.get(f"{foreign}/ti/results", params={"value": "hit.example.com"})
    assert history.status_code == 404
    # Own org path with the victim's ids: 404; own listings: empty.
    assert (await a.get(f"{own}/ti/runs/{run}")).status_code == 404
    assert (await a.get(f"{own}/ti/results/{result_id}")).status_code == 404
    assert (await a.get(f"{own}/analyses/{job_id}/iocs")).status_code == 404
    assert (await enrich_job(a, attacker.org_id, job_id)).status_code == 404
    assert (await a.get(f"{own}/ti/runs")).json()["total"] == 0
    mine = (await a.get(f"{own}/ti/results", params={"value": "hit.example.com"})).json()
    assert mine["total"] == 0 and mine["items"] == []
    assert (await a.get(f"{own}/ti/settings")).json()["excluded_suffixes"] == []
    integrations = (await a.get(f"{own}/integrations")).json()["items"]
    assert all(i["configured"] is False for i in integrations)
    # The attacker's own job with the same IOC values carries none of the victim's results.
    await enable(a, attacker.org_id)
    own_job = await succeeded_job(attacker)
    rows = (await a.get(f"{own}/analyses/{own_job}/iocs", params={"include": "enrichment"})).json()[
        "items"
    ]
    assert all(r["enrichment"] == [] for r in rows)


async def test_results_are_append_only_for_the_app_role(sent: Sent) -> None:
    owner = await _owner()
    run = await _run(owner, "hit.example.com")
    await add_result(owner.org_id, run)
    for statement in ("UPDATE ti_results SET found = false", "DELETE FROM ti_results"):
        with pytest.raises(DBAPIError):
            async with tenant_session(owner.org_id, None) as s:
                await s.execute(text(statement))
