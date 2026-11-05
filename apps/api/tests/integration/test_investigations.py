import asyncio
import uuid
from datetime import datetime
from typing import Any

import pytest
from httpx import AsyncClient

from app.core.tenancy import tenant_session
from app.modules.organizations.models import Organization
from tests.factories import csrf, register
from tests.integration.test_orgs_members import org_with_roles


def _url(org_id: uuid.UUID, suffix: str = "") -> str:
    return f"/api/v1/orgs/{org_id}/investigations{suffix}"


async def _create(client: AsyncClient, org_id: uuid.UUID, **body: Any) -> dict[str, Any]:
    payload = {"title": "Suspicious beaconing", "severity": "high"} | body
    response = await client.post(_url(org_id), json=payload, headers=csrf(client))
    assert response.status_code == 201, response.text
    return response.json()  # type: ignore[no-any-return]


# Closing, reopening and archiving need a reason since M6 (test_case_status covers the rule).
REASON = "Status change for the test"


async def _patch(client: AsyncClient, org_id: uuid.UUID, inv_id: str, **body: Any) -> Any:
    return await client.patch(_url(org_id, f"/{inv_id}"), json=body, headers=csrf(client))


async def test_create_and_get() -> None:
    reg = await register()
    created = await _create(reg.client, reg.org_id, description="Multi\nline\tnotes")
    assert created["case_ref"] == "CASE-00001"
    assert created["status"] == "open"
    assert created["evidence_count"] == 0
    assert created["created_by"] == str(reg.user_id)
    fetched = (await reg.client.get(_url(reg.org_id, f"/{created['id']}"))).json()
    assert fetched == created

    logs = (
        await reg.client.get(f"/api/v1/orgs/{reg.org_id}/audit-logs?action=investigation.created")
    ).json()
    assert logs["items"][0]["details"]["case_ref"] == "CASE-00001"


async def test_case_numbers_are_per_org_and_unique_under_concurrency() -> None:
    a = await register()
    b = await register()
    results = await asyncio.gather(
        *(_create(a.client, a.org_id, title=f"Case {i:03d}") for i in range(10))
    )
    assert sorted(r["case_number"] for r in results) == list(range(1, 11))
    assert (await _create(b.client, b.org_id))["case_number"] == 1


async def test_list_filters_search_sort_and_paginate() -> None:
    reg = await register()
    c = reg.client
    await _create(c, reg.org_id, title="Phishing wave", severity="medium")
    crit = await _create(c, reg.org_id, title="Ransomware on DC", severity="critical")
    low = await _create(c, reg.org_id, title="Odd DNS lookups", severity="low")
    await _patch(c, reg.org_id, low["id"], status="in_progress")

    def titles(page: dict[str, Any]) -> list[str]:
        return [i["title"] for i in page["items"]]

    base = _url(reg.org_id)
    assert titles((await c.get(base, params={"q": "ransom"})).json()) == ["Ransomware on DC"]
    assert titles((await c.get(base, params={"q": "case-00002"})).json()) == ["Ransomware on DC"]
    assert titles((await c.get(base, params={"status": "in_progress"})).json()) == [
        "Odd DNS lookups"
    ]
    assert titles((await c.get(base, params={"severity": "critical"})).json()) == [crit["title"]]
    by_sev = titles((await c.get(base, params={"sort": "-severity"})).json())
    assert by_sev == ["Ransomware on DC", "Phishing wave", "Odd DNS lookups"]
    newest = titles((await c.get(base)).json())
    assert newest[0] == "Odd DNS lookups"

    page = (await c.get(base, params={"limit": 2, "offset": 2})).json()
    assert page["total"] == 3 and len(page["items"]) == 1
    assert (await c.get(base, params={"sort": "title"})).status_code == 422


@pytest.mark.parametrize("q", ["%", "_", "\\", "100%_\\"])
async def test_like_wildcards_are_literal(q: str) -> None:
    reg = await register()
    await _create(reg.client, reg.org_id, title="Plain title")
    await _create(reg.client, reg.org_id, title="Exfil 100%_\\ done")
    page = (await reg.client.get(_url(reg.org_id), params={"q": q})).json()
    assert [i["title"] for i in page["items"]] == ["Exfil 100%_\\ done"]


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (["in_progress"], 200),
        (["closed"], 200),
        (["in_progress", "closed", "in_progress"], 200),  # reopen
        (["in_progress", "closed", "archived"], 200),
        (["archived"], 409),
        (["in_progress", "open"], 409),
    ],
)
async def test_status_transitions(path: list[str], expected: int) -> None:
    reg = await register()
    inv = await _create(reg.client, reg.org_id)
    *steps, last = path
    for step in steps:
        response = await _patch(
            reg.client, reg.org_id, inv["id"], status=step, status_reason=REASON
        )
        assert response.status_code == 200, response.text
    response = await _patch(reg.client, reg.org_id, inv["id"], status=last, status_reason=REASON)
    assert response.status_code == expected
    if expected == 409:
        assert response.json()["error"]["code"] == "invalid_transition"


async def test_archived_is_read_only() -> None:
    reg = await register()
    inv = await _create(reg.client, reg.org_id)
    for step in ("closed", "archived"):
        response = await _patch(
            reg.client, reg.org_id, inv["id"], status=step, status_reason=REASON
        )
        assert response.status_code == 200, response.text
    archived = (await reg.client.get(_url(reg.org_id, f"/{inv['id']}"))).json()
    assert archived["allowed_transitions"] == []
    response = await _patch(reg.client, reg.org_id, inv["id"], title="New title")
    assert (response.status_code, response.json()["error"]["code"]) == (
        409,
        "investigation_archived",
    )


async def test_update_records_diff_and_bumps_updated_at() -> None:
    reg = await register()
    inv = await _create(reg.client, reg.org_id)
    response = await _patch(
        reg.client,
        reg.org_id,
        inv["id"],
        title="Renamed case",
        severity="critical",
        description="x",
    )
    body = response.json()
    assert (body["title"], body["severity"]) == ("Renamed case", "critical")
    updated, created = (datetime.fromisoformat(x) for x in (body["updated_at"], inv["updated_at"]))
    assert updated > created
    logs = (
        await reg.client.get(f"/api/v1/orgs/{reg.org_id}/audit-logs?action=investigation.updated")
    ).json()
    changes = logs["items"][0]["details"]["changes"]
    assert changes["title"] == {"from": "Suspicious beaconing", "to": "Renamed case"}
    assert changes["severity"] == {"from": "high", "to": "critical"}
    assert changes["description"] == {"changed": True}


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"title": None},
        {"title": "ab"},
        {"description": "nul\u0000byte"},
        {"status": "deleted"},
        {"titel": "typo"},
        {"title": "evil\u202etxt.exe"},
    ],
)
async def test_invalid_updates_are_rejected(body: dict[str, Any]) -> None:
    reg = await register()
    inv = await _create(reg.client, reg.org_id)
    response = await _patch(reg.client, reg.org_id, inv["id"], **body)
    assert response.status_code == 422


async def test_permissions_and_tenant_isolation() -> None:
    org = await org_with_roles()
    other = await register()
    inv = await _create(org.clients["analyst"], org.org_id)

    viewer = org.clients["viewer"]
    assert (await viewer.get(_url(org.org_id, f"/{inv['id']}"))).status_code == 200
    assert (await _patch(viewer, org.org_id, inv["id"], title="Viewer edit")).status_code == 403
    viewer_create = await viewer.post(
        _url(org.org_id), json={"title": "Nope", "severity": "low"}, headers=csrf(viewer)
    )
    assert viewer_create.status_code == 403

    # Another org's member: 404 on the org route, and 404 using their own org + foreign id.
    assert (await other.client.get(_url(org.org_id, f"/{inv['id']}"))).status_code == 404
    assert (await other.client.get(_url(other.org_id, f"/{inv['id']}"))).status_code == 404
    assert (await _patch(other.client, other.org_id, inv["id"], title="Hijack")).status_code == 404


async def test_null_field_error_points_at_the_field() -> None:
    reg = await register()
    inv = await _create(reg.client, reg.org_id)
    response = await _patch(reg.client, reg.org_id, inv["id"], title=None)
    assert response.json()["error"]["details"][0]["loc"] == ["body", "title"]


async def test_allowed_transitions_exposed() -> None:
    reg = await register()
    inv = await _create(reg.client, reg.org_id)
    assert inv["allowed_transitions"] == ["closed", "in_progress"]


async def test_same_status_patch_is_noop_without_audit() -> None:
    reg = await register()
    inv = await _create(reg.client, reg.org_id)
    response = await _patch(reg.client, reg.org_id, inv["id"], status="open")
    assert response.status_code == 200
    url = f"/api/v1/orgs/{reg.org_id}/audit-logs?action=investigation.updated"
    assert (await reg.client.get(url)).json()["total"] == 0


async def test_numeric_query_matches_title_or_case_number() -> None:
    reg = await register()
    await _create(reg.client, reg.org_id, title="First case")
    await _create(reg.client, reg.org_id, title="Second case")
    await _create(reg.client, reg.org_id, title="Port 2 scan")
    page = (await reg.client.get(_url(reg.org_id), params={"q": "2"})).json()
    assert sorted(i["title"] for i in page["items"]) == ["Port 2 scan", "Second case"]


@pytest.mark.parametrize(("suffix", "param"), [("investigations", "q"), ("audit-logs", "action")])
async def test_nul_in_search_terms_is_422_not_500(suffix: str, param: str) -> None:
    reg = await register()
    response = await reg.client.get(
        f"/api/v1/orgs/{reg.org_id}/{suffix}", params={param: "a" + chr(0) + "b"}
    )
    assert (response.status_code, response.json()["error"]["code"]) == (422, "validation_error")


async def test_create_rejects_control_chars_and_foreign_org() -> None:
    reg = await register()
    other = await register()
    bad = await reg.client.post(
        _url(reg.org_id),
        json={"title": "tab" + chr(9) + "here", "severity": "low"},
        headers=csrf(reg.client),
    )
    assert bad.status_code == 422
    foreign = await reg.client.post(
        _url(other.org_id), json={"title": "Sneaky", "severity": "low"}, headers=csrf(reg.client)
    )
    assert foreign.status_code == 404


async def test_case_number_does_not_touch_org_updated_at() -> None:
    reg = await register()
    async with tenant_session(reg.org_id, reg.user_id) as s:
        org = await s.get(Organization, reg.org_id)
        assert org is not None
        before = org.updated_at
    await _create(reg.client, reg.org_id)
    async with tenant_session(reg.org_id, reg.user_id) as s:
        org = await s.get(Organization, reg.org_id, populate_existing=True)
        assert org is not None
        assert org.updated_at == before
        assert org.next_case_number == 2
