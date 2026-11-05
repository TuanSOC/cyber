"""Related cases (M7 phase 4): other cases of the org ranked by distinct shared non-common
keys (ties: the latest shared `last_seen`), common keys excluded and counted, archived cases
included and labelled, never another org's case."""

import uuid

import pytest
from sqlalchemy import update

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.investigations.models import Investigation, InvestigationStatus
from tests.case_helpers import seed_case
from tests.integration.seed import Tenant
from tests.integration.test_correlation_indexer import (
    extra_job,
    job_with_iocs,
    member_client,
    seed_indexed,
)
from tests.ops_helpers import SHARED_IOCS

API = "/api/v1/orgs"
SHARED = dict(SHARED_IOCS)


async def _job_with_one_shared_ioc(t: Tenant, case_id: uuid.UUID) -> uuid.UUID:
    """A job sharing only the domain (plus a value of its own)."""
    own = f"only-{uuid.uuid4().hex[:8]}.example-corp.net"
    return await job_with_iocs(t, case_id, [("domain", SHARED["domain"]), ("domain", own)])


async def test_cases_are_ranked_by_shared_keys() -> None:
    seed = await seed_indexed()
    t = seed.org_a
    case_c = await seed_case(t, title="Weakly related case")
    await _job_with_one_shared_ioc(t, case_c)
    c = await member_client(t.org_id)
    r = await c.get(f"{API}/{t.org_id}/investigations/{seed.case_a1}/related")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["investigation_id"] == str(seed.case_a1)
    assert [i["investigation_id"] for i in body["items"]] == [str(seed.case_a2), str(case_c)]
    first, second = body["items"]
    assert (first["shared_keys"], second["shared_keys"]) == (4, 1)
    assert first["kinds"] == {"domain": 1, "ipv4": 1, "ja3": 1, "sha256": 1}
    assert second["kinds"] == {"domain": 1}
    assert first["case_ref"].startswith("CASE-") and first["title"] == "Correlated case A2"
    assert first["status"] == "open" and first["last_seen"] is not None
    assert body["common_keys_excluded"] == 0
    # Up to 5 sample shared keys per case (M7 follow-up), each a real shared key.
    assert {(k["kind"], k["value"]) for k in first["sample_keys"]} == {
        ("domain", SHARED["domain"]),
        ("ipv4", SHARED["ip"]),
        ("ja3", SHARED["ja3"]),
        ("sha256", SHARED["file_sha256"]),
    }
    assert all(len(k["key"]) == 64 for k in first["sample_keys"])
    assert [(k["kind"], k["value"]) for k in second["sample_keys"]] == [
        ("domain", SHARED["domain"])
    ]
    # Org B's case shares every value and never shows up.
    assert str(seed.case_b) not in {i["investigation_id"] for i in body["items"]}


async def test_common_keys_are_excluded_from_the_ranking(monkeypatch: pytest.MonkeyPatch) -> None:
    seed = await seed_indexed()
    t = seed.org_a
    case_c = await seed_case(t, title="Third case")
    await _job_with_one_shared_ioc(t, case_c)  # the domain is now in 3 jobs
    monkeypatch.setattr(get_settings(), "correlation_common_key_jobs", 2)
    c = await member_client(t.org_id)
    body = (await c.get(f"{API}/{t.org_id}/investigations/{seed.case_a1}/related")).json()
    # The domain (3 jobs) is common: case C shared only it, case A2 keeps its 3 other keys.
    assert [(i["investigation_id"], i["shared_keys"]) for i in body["items"]] == [
        (str(seed.case_a2), 3)
    ]
    assert "domain" not in body["items"][0]["kinds"]
    # A common key is never offered as a sample either.
    assert {k["kind"] for k in body["items"][0]["sample_keys"]} == {"ipv4", "ja3", "sha256"}
    assert body["common_keys_excluded"] == 1


async def test_archived_cases_are_included_and_labelled() -> None:
    seed = await seed_indexed()
    t = seed.org_a
    async with tenant_session(t.org_id, t.owner_id) as s:
        await s.execute(
            update(Investigation)
            .where(Investigation.id == seed.case_a2)
            .values(status=InvestigationStatus.ARCHIVED)
        )
    c = await member_client(t.org_id)
    body = (await c.get(f"{API}/{t.org_id}/investigations/{seed.case_a1}/related")).json()
    [item] = body["items"]
    assert (item["investigation_id"], item["status"]) == (str(seed.case_a2), "archived")


async def test_a_case_with_several_jobs_counts_distinct_keys() -> None:
    seed = await seed_indexed()
    await extra_job(seed.org_a, seed.case_a2)  # case A2 now has two jobs with the same keys
    c = await member_client(seed.org_a.org_id)
    body = (await c.get(f"{API}/{seed.org_a.org_id}/investigations/{seed.case_a1}/related")).json()
    [item] = body["items"]
    assert item["shared_keys"] == 4


async def test_a_case_without_keys_or_of_another_org() -> None:
    seed = await seed_indexed()
    t = seed.org_a
    lonely = await seed_case(t, title="No evidence yet")
    c = await member_client(t.org_id)
    body = (await c.get(f"{API}/{t.org_id}/investigations/{lonely}/related")).json()
    assert (body["items"], body["common_keys_excluded"]) == ([], 0)
    r = await c.get(f"{API}/{t.org_id}/investigations/{seed.case_b}/related")
    assert r.status_code == 404


async def test_at_most_five_sample_keys_per_case() -> None:
    seed = await seed_indexed()
    t = seed.org_a
    values = [("domain", f"s{i}-{uuid.uuid4().hex[:6]}.example-corp.net") for i in range(6)]
    case_c = await seed_case(t, title="Six shared values C")
    case_d = await seed_case(t, title="Six shared values D")
    await job_with_iocs(t, case_c, values)
    await job_with_iocs(t, case_d, values)
    c = await member_client(t.org_id)
    body = (await c.get(f"{API}/{t.org_id}/investigations/{case_c}/related")).json()
    [item] = body["items"]
    assert item["investigation_id"] == str(case_d) and item["shared_keys"] == 6
    samples = [k["value"] for k in item["sample_keys"]]
    assert len(samples) == 5 and set(samples) <= {v for _, v in values}
