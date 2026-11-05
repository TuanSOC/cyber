"""Correlation reads (M7 phase 4): the job pivot ("also seen in") and the key lookup.

Cross-case hits inside one org, never across orgs; common keys flagged; deep-link data
(job, analyzer, evidence); the server normalizes the looked-up value (`422
search_query_invalid` otherwise, never echoing it); the keys join the M6 collection items by
`ioc_key` (RT8) and survive a purge of the job's results (RT9).

M7 follow-up: the pivot's `source_ids` (the IOC row ids), `kind` / `include_unique` / cursor
paging; the lookup is a POST with the value in the body (never in a URL, RT13) and carries
the stored threat intel answer count and the IOC collections holding the key.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select, text

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.correlation import indexer
from app.modules.correlation import service as correlation_service
from app.modules.correlation.normalize import correlation_key
from app.modules.pcap_analysis.models import Ioc
from app.modules.threat_intel.models import TiEnrichmentRun, TiResult
from tests.factories import csrf
from tests.integration.seed import Tenant
from tests.integration.test_correlation_indexer import (
    extra_job,
    job_with_iocs,
    member_client,
    seed_indexed,
)
from tests.ops_helpers import SHARED_IOCS, _job_with_iocs

API = "/api/v1/orgs"
JA3 = dict(SHARED_IOCS)["ja3"]
DOMAIN = dict(SHARED_IOCS)["domain"]


async def lookup(c: AsyncClient, org_id: uuid.UUID, kind: str, value: str):  # type: ignore[no-untyped-def]
    """`POST /correlations/lookup` with the value in the body."""
    return await c.post(
        f"{API}/{org_id}/correlations/lookup",
        json={"kind": kind, "value": value},
        headers=csrf(c),
    )


async def test_the_job_pivot_lists_other_cases_of_the_org_only() -> None:
    seed = await seed_indexed()
    c = await member_client(seed.org_a.org_id)
    r = await c.get(f"{API}/{seed.org_a.org_id}/analyses/{seed.job_a1}/correlations")
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["indexed"], body["truncated"], body["total_keys"]) == (True, False, 4)
    # Sorted by shared-case count, then kind, then value.
    assert [i["kind"] for i in body["items"]] == ["domain", "ipv4", "ja3", "sha256"]
    for item in body["items"]:
        # Org B carries the same values: never counted.
        assert (item["other_jobs"], item["other_cases"], item["common"]) == (1, 1, False)
        [case] = item["top_cases"]
        assert case["investigation_id"] == str(seed.case_a2)
        assert case["case_ref"].startswith("CASE-") and case["title"] == "Correlated case A2"
        assert case["jobs"] == 1 and case["last_seen"] is not None
        assert item["first_seen"] is not None and item["last_seen"] is not None
    ja3 = next(i for i in body["items"] if i["kind"] == "ja3")
    assert ja3["value"] == JA3


async def test_keys_seen_nowhere_else_are_omitted_and_same_case_jobs_count() -> None:
    seed = await seed_indexed()
    t = seed.org_a
    # A second job in case A1: the keys gain another job but no other case.
    await extra_job(t, seed.case_a1)
    c = await member_client(t.org_id)
    body = (await c.get(f"{API}/{t.org_id}/analyses/{seed.job_a1}/correlations")).json()
    assert {(i["other_jobs"], i["other_cases"]) for i in body["items"]} == {(2, 1)}
    # Org B's only job: its keys exist nowhere else in org B.
    cb = await member_client(seed.org_b.org_id)
    body_b = (await cb.get(f"{API}/{seed.org_b.org_id}/analyses/{seed.job_b}/correlations")).json()
    assert body_b["items"] == [] and body_b["total_keys"] == 4


async def test_an_unindexed_job_answers_indexed_false() -> None:
    seed = await seed_indexed()
    job_id = await _job_with_iocs(seed.org_a, seed.case_a1)  # no index row yet
    c = await member_client(seed.org_a.org_id)
    body = (await c.get(f"{API}/{seed.org_a.org_id}/analyses/{job_id}/correlations")).json()
    assert (body["indexed"], body["items"], body["total_keys"]) == (False, [], 0)


async def test_the_pivot_of_another_orgs_job_is_404() -> None:
    seed = await seed_indexed()
    c = await member_client(seed.org_a.org_id)
    r = await c.get(f"{API}/{seed.org_a.org_id}/analyses/{seed.job_b}/correlations")
    assert r.status_code == 404
    r = await c.get(f"{API}/{seed.org_a.org_id}/analyses/{uuid.uuid4()}/correlations")
    assert r.status_code == 404


async def test_common_keys_are_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    seed = await seed_indexed()
    await extra_job(seed.org_a, seed.case_a1)
    monkeypatch.setattr(get_settings(), "correlation_common_key_jobs", 2)  # 3 jobs > 2
    c = await member_client(seed.org_a.org_id)
    body = (await c.get(f"{API}/{seed.org_a.org_id}/analyses/{seed.job_a1}/correlations")).json()
    assert all(i["common"] for i in body["items"])
    r = await lookup(c, seed.org_a.org_id, "ipv4", "203.0.113.77")
    assert r.json()["common"] is True


async def test_the_lookup_normalizes_and_lists_occurrences() -> None:
    seed = await seed_indexed()
    c = await member_client(seed.org_a.org_id)
    r = await lookup(c, seed.org_a.org_id, "domain", "  C2.Shared-Example.NET. ")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["value_norm"] == "c2.shared-example.net" and len(body["key"]) == 64
    assert (body["jobs"], body["cases"], body["common"]) == (2, 2, False)
    assert {i["job_id"] for i in body["items"]} == {str(seed.job_a1), str(seed.job_a2)}
    for item in body["items"]:
        # Deep-link descriptors: the job (and its analyzer tab) and the evidence.
        assert item["analyzer"] == "pcap" and item["evidence_filename"] == "shared.pcap"
        assert item["case_ref"].startswith("CASE-") and item["evidence_id"]
    ja3 = (await lookup(c, seed.org_a.org_id, "ja3", JA3)).json()
    assert ja3["jobs"] == 2
    # Threat intel never looks up a JA3: no count rather than a misleading zero.
    assert ja3["ti_results"] is None
    unseen = (await lookup(c, seed.org_a.org_id, "ipv4", "198.51.100.200")).json()
    assert (unseen["jobs"], unseen["items"], unseen["first_seen"]) == (0, [], None)
    assert (unseen["ti_results"], unseen["collections"], unseen["collections_total"]) == (
        0,
        [],
        0,
    )


@pytest.mark.parametrize(
    ("kind", "value"),
    [("ipv4", "not-an-ip-secret-value"), ("ipv4", "2001:db8::1"), ("sha256", "abc123secret")],
)
async def test_a_value_that_does_not_normalize_is_422_without_echo(kind: str, value: str) -> None:
    seed = await seed_indexed()
    c = await member_client(seed.org_a.org_id)
    r = await lookup(c, seed.org_a.org_id, kind, value)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "search_query_invalid"
    assert value not in r.text


async def test_keys_join_the_m6_collection_items() -> None:
    """RT8: an analyst's collection item and the job key are the same `ioc_key`."""
    seed = await seed_indexed()
    t = seed.org_a
    c = await member_client(t.org_id)
    created = await c.post(
        f"{API}/{t.org_id}/investigations/{seed.case_a1}/ioc-collections",
        json={"name": "Shared infra"},
        headers=csrf(c),
    )
    assert created.status_code == 201, created.text
    items = [{"type": ioc_type, "value": value} for ioc_type, value in SHARED_IOCS]
    added = await c.post(
        f"{API}/{t.org_id}/ioc-collections/{created.json()['id']}/items",
        json={"items": items},
        headers=csrf(c),
    )
    assert added.status_code == 200 and added.json()["added"] == 4, added.text
    async with tenant_session(t.org_id, None) as s:
        joined = await s.execute(
            text(
                "SELECT count(DISTINCT i.ioc_key) FROM ioc_collection_items i "
                "JOIN correlation_keys k ON k.key = i.ioc_key AND k.kind = i.ioc_type "
                "WHERE k.job_id = :job"
            ),
            {"job": seed.job_a1},
        )
        assert joined.scalar_one() == 4


async def test_keys_survive_a_purge_of_the_job_results(owner_engine) -> None:  # type: ignore[no-untyped-def]
    """RT9: a closed case whose results rows were purged still correlates."""
    seed = await seed_indexed()
    async with owner_engine.begin() as conn:  # the retention worker's DELETE, as the owner
        await conn.execute(text("SET LOCAL app.org_id = '" + str(seed.org_a.org_id) + "'"))
        await conn.execute(text("DELETE FROM iocs WHERE job_id = :j"), {"j": seed.job_a2})
    assert await indexer.index_pending(10) == 0  # the job stays indexed: no rebuild churn
    c = await member_client(seed.org_a.org_id)
    body = (await c.get(f"{API}/{seed.org_a.org_id}/analyses/{seed.job_a1}/correlations")).json()
    assert len(body["items"]) == 4 and all(i["other_cases"] == 1 for i in body["items"])


# --- M7 follow-up: the pivot's source ids, filters and paging ---------------------------------


async def test_the_pivot_carries_the_ioc_row_ids_of_this_job() -> None:
    """The IOC tab joins its rows by id (RT8), never by re-normalizing values."""
    seed = await seed_indexed()
    t = seed.org_a
    async with tenant_session(t.org_id, t.owner_id) as s:
        rows = (await s.execute(select(Ioc.id, Ioc.type).where(Ioc.job_id == seed.job_a1))).all()
    ids = {str(i) for i, _ in rows}
    c = await member_client(t.org_id)
    body = (await c.get(f"{API}/{t.org_id}/analyses/{seed.job_a1}/correlations")).json()
    for item in body["items"]:
        [source_id] = item["source_ids"]
        assert source_id in ids
    assert len({i["source_ids"][0] for i in body["items"]}) == 4
    # Another job's rows never appear in this job's pivot.
    other = (await c.get(f"{API}/{t.org_id}/analyses/{seed.job_a2}/correlations")).json()
    assert not {i["source_ids"][0] for i in other["items"]} & ids


async def test_the_pivot_filters_by_kind_and_includes_unique_keys_on_request() -> None:
    seed = await seed_indexed()
    t = seed.org_a
    own = f"only-{uuid.uuid4().hex[:8]}.example-corp.net"
    job = await job_with_iocs(t, seed.case_a1, [("domain", DOMAIN), ("domain", own)])
    c = await member_client(t.org_id)
    url = f"{API}/{t.org_id}/analyses/{job}/correlations"
    body = (await c.get(url)).json()
    assert [i["value"] for i in body["items"]] == [DOMAIN] and body["total_keys"] == 2
    unique = (await c.get(url, params={"include_unique": "true"})).json()
    assert [(i["value"], i["other_jobs"]) for i in unique["items"]] == [(DOMAIN, 2), (own, 0)]
    assert unique["next_cursor"] is None
    by_kind = (await c.get(url, params={"kind": "ipv4", "include_unique": "true"})).json()
    assert by_kind["items"] == [] and by_kind["total_keys"] == 2
    assert (await c.get(url, params={"kind": "nope"})).status_code == 422


async def test_the_pivot_pages_with_a_cursor(monkeypatch: pytest.MonkeyPatch) -> None:
    seed = await seed_indexed()
    t = seed.org_a
    monkeypatch.setattr(correlation_service, "JOB_ITEMS", 3)
    c = await member_client(t.org_id)
    url = f"{API}/{t.org_id}/analyses/{seed.job_a1}/correlations"
    first = (await c.get(url)).json()
    assert len(first["items"]) == 3 and first["next_cursor"]
    second = (await c.get(url, params={"cursor": first["next_cursor"]})).json()
    assert len(second["items"]) == 1 and second["next_cursor"] is None
    seen = [i["key"] for i in first["items"] + second["items"]]
    assert len(set(seen)) == 4
    for bad in ("not-a-cursor", "eyJvIjotMX0", "eyJvIjoiMSJ9"):
        r = await c.get(url, params={"cursor": bad})
        assert r.status_code == 400 and r.json()["error"]["code"] == "invalid_cursor"


# --- M7 follow-up: the POST lookup ---------------------------------------------------------


async def test_the_lookup_is_a_post_and_the_value_never_travels_in_a_url() -> None:
    seed = await seed_indexed()
    c = await member_client(seed.org_a.org_id)
    base = f"{API}/{seed.org_a.org_id}/correlations"
    # The old GET form is gone (an IOC value in a query string reaches the access logs).
    r = await c.get(base, params={"kind": "domain", "value": DOMAIN})
    assert r.status_code in (404, 405)
    assert (await c.get(f"{base}/lookup")).status_code == 405
    # CSRF applies as on every POST.
    no_csrf = await c.post(f"{base}/lookup", json={"kind": "domain", "value": DOMAIN})
    assert no_csrf.status_code == 403
    extra = await c.post(
        f"{base}/lookup",
        json={"kind": "domain", "value": DOMAIN, "more": 1},
        headers=csrf(c),
    )
    assert extra.status_code == 422
    ok = await lookup(c, seed.org_a.org_id, "domain", DOMAIN)
    assert ok.status_code == 200 and ok.json()["jobs"] == 2


async def test_the_lookup_value_is_absent_from_the_logs(caplog: pytest.LogCaptureFixture) -> None:
    seed = await seed_indexed()
    c = await member_client(seed.org_a.org_id)
    secret = "never-logged-secret.example-corp.net"
    caplog.set_level("DEBUG")
    assert (await lookup(c, seed.org_a.org_id, "domain", secret)).status_code == 200
    assert (await lookup(c, seed.org_a.org_id, "ipv4", secret)).status_code == 422
    assert secret not in caplog.text


async def _ti_answer(t: Tenant, kind: str, value: str, n: int = 1) -> None:
    """`n` stored threat intel answers for the value (one run each)."""
    normalized = correlation_key(kind, value)
    assert normalized is not None
    _, key, value_norm = normalized
    finished = datetime.now(UTC) - timedelta(days=1)
    async with tenant_session(t.org_id, t.owner_id) as s:
        for _ in range(n):
            run = TiEnrichmentRun(
                id=uuid.uuid4(),
                organization_id=t.org_id,
                scope="manual",
                requested_by=t.owner_id,
                providers=["mock"],
                status="completed",
                deadline_at=finished + timedelta(minutes=30),
                started_at=finished - timedelta(minutes=1),
                finished_at=finished,
            )
            s.add(run)
            await s.flush()
            s.add(
                TiResult(
                    organization_id=t.org_id,
                    run_id=run.id,
                    provider="mock",
                    ioc_type=kind,
                    value_norm=value_norm,
                    ioc_key=key,
                    status="ok",
                    found=True,
                    summary={"provider": "mock", "label": "seen"},
                    fetched_at=finished,
                    expires_at=finished + timedelta(hours=1),
                )
            )


async def test_the_lookup_counts_ti_answers_and_lists_collections_of_the_org_only() -> None:
    seed = await seed_indexed()
    a, b = seed.org_a, seed.org_b
    await _ti_answer(a, "domain", DOMAIN, n=2)
    await _ti_answer(b, "domain", DOMAIN, n=3)  # another org's answers: never counted
    c = await member_client(a.org_id)
    created = await c.post(
        f"{API}/{a.org_id}/investigations/{seed.case_a2}/ioc-collections",
        json={"name": "Shared infra"},
        headers=csrf(c),
    )
    assert created.status_code == 201, created.text
    collection_id = created.json()["id"]
    added = await c.post(
        f"{API}/{a.org_id}/ioc-collections/{collection_id}/items",
        json={"items": [{"type": "domain", "value": DOMAIN}]},
        headers=csrf(c),
    )
    assert added.status_code == 200, added.text
    cb = await member_client(b.org_id)
    other = await cb.post(
        f"{API}/{b.org_id}/investigations/{seed.case_b}/ioc-collections",
        json={"name": "Other org set"},
        headers=csrf(cb),
    )
    await cb.post(
        f"{API}/{b.org_id}/ioc-collections/{other.json()['id']}/items",
        json={"items": [{"type": "domain", "value": DOMAIN}]},
        headers=csrf(cb),
    )
    body = (await lookup(c, a.org_id, "domain", DOMAIN.upper())).json()
    assert body["ti_results"] == 2
    assert body["collections_total"] == 1
    [held] = body["collections"]
    assert held["collection_id"] == collection_id
    assert held["investigation_id"] == str(seed.case_a2)
    assert held["name"] == "Shared infra" and held["archived"] is False
    assert held["case_ref"].startswith("CASE-")
    # A value no collection holds, and a kind no collection item has.
    ip = (await lookup(c, a.org_id, "ipv4", "203.0.113.77")).json()
    assert (ip["ti_results"], ip["collections_total"]) == (0, 0)
