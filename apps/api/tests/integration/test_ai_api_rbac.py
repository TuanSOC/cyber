"""Role x route matrix for every AI analyst route (M5 phase 7): viewers read (status, runs,
outputs, the pseudonymized context, usage; never a secret), analysts also preview, request
runs and reveal a context's pseudonym map, admins and owners also manage providers and AI
settings."""

import uuid
from collections.abc import Callable
from typing import Any

import pytest
from httpx import AsyncClient, Response

from app.core.config import get_settings
from app.modules.organizations.models import MemberRole
from tests.ai_api_helpers import (
    API,
    AiSent,
    capture_ai_sends,
    enable_ai,
    put_provider,
    tenant_of,
    use_fake_builder,
)
from tests.ai_helpers import AI_SENTINEL_KEY, seed_job
from tests.factories import Registered, csrf
from tests.integration.test_orgs_members import org_with_roles

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
        (READ, "list providers", lambda c, b, ids: c.get(f"{b}/ai/providers")),
        (READ, "get settings", lambda c, b, ids: c.get(f"{b}/ai/settings")),
        (READ, "usage", lambda c, b, ids: c.get(f"{b}/ai/usage")),
        (READ, "list runs", lambda c, b, ids: c.get(f"{b}/ai/runs")),
        (READ, "get run", lambda c, b, ids: c.get(f"{b}/ai/runs/{ids['run']}")),
        (READ, "get context", lambda c, b, ids: c.get(f"{b}/ai/runs/{ids['run']}/context")),
        (
            WRITE,
            "reveal context",
            lambda c, b, ids: c.get(f"{b}/ai/runs/{ids['run']}/context", params={"reveal": True}),
        ),
        (
            WRITE,
            "preview",
            lambda c, b, ids: c.post(
                f"{b}/ai/context-preview",
                json={"task": "ioc_correlation", "job_id": ids["job"]},
                headers=csrf(c),
            ),
        ),
        (
            WRITE,
            "request run",
            lambda c, b, ids: c.post(
                f"{b}/ai/runs",
                json={"task": "attack_mapping", "job_id": ids["job"], "regenerate": True},
                headers=csrf(c),
            ),
        ),
        (
            MANAGE,
            "put provider",
            lambda c, b, ids: c.put(
                f"{b}/ai/providers/mock",
                json={"api_key": AI_SENTINEL_KEY, "enabled": True, "acknowledge_terms": True},
                headers=csrf(c),
            ),
        ),
        (
            MANAGE,
            "verify",
            lambda c, b, ids: c.post(f"{b}/ai/providers/mock/verify", headers=csrf(c)),
        ),
        (
            MANAGE,
            "put settings",
            lambda c, b, ids: c.put(
                f"{b}/ai/settings",
                json={"internal_suffixes": ["corp.acme.net"], "include_ti": True},
                headers=csrf(c),
            ),
        ),
        (
            MANAGE,
            "remove key",
            lambda c, b, ids: c.delete(f"{b}/ai/providers/mock/key", headers=csrf(c)),
        ),
    ]


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> AiSent:
    use_fake_builder(monkeypatch)
    return capture_ai_sends(monkeypatch)


@pytest.mark.parametrize("role", list(MemberRole))
async def test_ai_role_matrix(
    role: MemberRole, sent: AiSent, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "ai_active_runs_per_org", 100)
    monkeypatch.setattr(get_settings(), "ai_runs_per_user_10min", 100)
    org = await org_with_roles()
    owner = org.clients["owner"]
    await enable_ai(owner, org.org_id)
    members = (await owner.get(f"{API}/{org.org_id}/members")).json()["items"]
    owner_id = next(m["user_id"] for m in members if m["email"] == org.emails["owner"])
    reg = Registered(owner, uuid.UUID(owner_id), org.org_id, org.emails["owner"], {})
    job_id = await seed_job(await tenant_of(reg))
    created = await owner.post(
        f"{API}/{org.org_id}/ai/runs",
        json={"task": "summarize_pcap", "job_id": str(job_id)},
        headers=csrf(owner),
    )
    assert created.status_code == 202, created.text
    ids = {"job": str(job_id), "run": created.json()["run"]["id"]}

    client = org.clients[role.value]
    base = f"{API}/{org.org_id}"
    for kind, name, call in _routes():
        if name == "remove key":
            await put_provider(owner, org.org_id, api_key=AI_SENTINEL_KEY)  # a key to remove
        response: Response = await call(client, base, ids)
        if kind in ALLOWED[role]:
            assert 200 <= response.status_code < 300, (role, name, response.text)
        else:
            assert response.status_code == 403, (role, name, response.status_code)
        assert AI_SENTINEL_KEY not in response.text
