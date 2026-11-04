"""Role x route matrix for every threat intel route (M4 phase 5): viewers read, analysts also
request enrichment, admins and owners also manage integrations and TI settings."""

import uuid
from collections.abc import Callable
from typing import Any

import pytest
from httpx import AsyncClient, Response

from app.modules.organizations.models import MemberRole
from app.modules.threat_intel import service_runs
from tests.factories import Registered, csrf
from tests.integration.test_orgs_members import org_with_roles
from tests.ti_api_helpers import API, Sent, add_result, capture_sends, enable, succeeded_job
from tests.ti_helpers import SENTINEL_KEY

READ, WRITE, MANAGE = "read", "write", "manage"
ALLOWED = {
    MemberRole.VIEWER: {READ},
    MemberRole.ANALYST: {READ, WRITE},
    MemberRole.ADMIN: {READ, WRITE, MANAGE},
    MemberRole.OWNER: {READ, WRITE, MANAGE},
}

Call = Callable[[AsyncClient, str, dict[str, str]], Any]


def _routes() -> list[tuple[str, str, Call]]:
    return [
        (READ, "list integrations", lambda c, b, ids: c.get(f"{b}/integrations")),
        (READ, "get settings", lambda c, b, ids: c.get(f"{b}/ti/settings")),
        (READ, "list runs", lambda c, b, ids: c.get(f"{b}/ti/runs")),
        (READ, "get run", lambda c, b, ids: c.get(f"{b}/ti/runs/{ids['run']}")),
        (
            READ,
            "history",
            lambda c, b, ids: c.get(f"{b}/ti/results", params={"value": "hit.example.com"}),
        ),
        (READ, "get result", lambda c, b, ids: c.get(f"{b}/ti/results/{ids['result']}")),
        (
            READ,
            "ioc enrichment",
            lambda c, b, ids: c.get(
                f"{b}/analyses/{ids['job']}/iocs", params={"include": "enrichment"}
            ),
        ),
        (
            WRITE,
            "lookup",
            lambda c, b, ids: c.post(
                f"{b}/ti/lookups", json={"values": [{"value": "hit.example.com"}]}, headers=csrf(c)
            ),
        ),
        (
            WRITE,
            "job enrichment",
            lambda c, b, ids: c.post(
                f"{b}/analyses/{ids['job']}/enrichments", json={}, headers=csrf(c)
            ),
        ),
        (
            MANAGE,
            "put integration",
            lambda c, b, ids: c.put(
                f"{b}/integrations/mock",
                json={"api_key": SENTINEL_KEY, "enabled": True, "acknowledge_terms": True},
                headers=csrf(c),
            ),
        ),
        (
            MANAGE,
            "verify",
            lambda c, b, ids: c.post(f"{b}/integrations/mock/verify", headers=csrf(c)),
        ),
        (
            MANAGE,
            "put settings",
            lambda c, b, ids: c.put(
                f"{b}/ti/settings", json={"excluded_suffixes": ["corp.acme.net"]}, headers=csrf(c)
            ),
        ),
        (
            MANAGE,
            "remove key",
            lambda c, b, ids: c.delete(f"{b}/integrations/mock/key", headers=csrf(c)),
        ),
    ]


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> Sent:
    return capture_sends(monkeypatch)


@pytest.mark.parametrize("role", list(MemberRole))
async def test_ti_role_matrix(
    role: MemberRole, sent: Sent, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service_runs, "MAX_ACTIVE_RUNS_PER_ORG", 100)
    org = await org_with_roles()
    owner = org.clients["owner"]
    await enable(owner, org.org_id)
    reg = Registered(owner, uuid.uuid4(), org.org_id, org.emails["owner"], {})
    job_id = await succeeded_job(reg)
    created = await owner.post(
        f"{API}/{org.org_id}/ti/lookups",
        json={"values": [{"value": "hit.example.com"}]},
        headers=csrf(owner),
    )
    run_id = created.json()["run"]["id"]
    result_id = await add_result(org.org_id, run_id)
    ids = {"job": str(job_id), "run": run_id, "result": str(result_id)}

    client = org.clients[role.value]
    base = f"{API}/{org.org_id}"
    for kind, name, call in _routes():
        if name == "remove key":
            await enable(owner, org.org_id)  # make sure there is a key to remove
        response: Response = await call(client, base, ids)
        if kind in ALLOWED[role]:
            assert 200 <= response.status_code < 300, (role, name, response.text)
        else:
            assert response.status_code == 403, (role, name, response.status_code)
        assert SENTINEL_KEY not in response.text
