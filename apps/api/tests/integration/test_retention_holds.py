"""Legal hold routes (M7 phase 3): place (case or org scope), release once, list, audit; the
case hold is published to the retention worker (`s3_sync: pending`, RT5); a released hold keeps
protecting for the delay (RT1); `legal_hold` on case and evidence reads."""

import uuid
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.organizations.models import MemberRole
from tests.case_helpers import seed_case, seed_evidence
from tests.factories import add_member, csrf, login, make_user, unique_email
from tests.integration.test_retention_purge import Captured, captured, owner_tenant
from tests.ops_helpers import seed_released_hold

API = "/api/v1/orgs"
__all__ = ["captured"]  # the shared fixture


async def _audit(org_id: uuid.UUID, action: str) -> list[dict[str, Any]]:
    async with tenant_session(org_id, None) as s:
        rows = await s.execute(
            text("SELECT details FROM audit_logs WHERE action = :a ORDER BY occurred_at"),
            {"a": action},
        )
        return [r for (r,) in rows.all()]


async def test_a_case_hold_is_placed_published_and_flagged(captured: Captured) -> None:
    reg, t = await owner_tenant()
    evidence_id = await seed_evidence(t, t.investigation_id)
    c = reg.client
    response = await c.post(
        f"{API}/{t.org_id}/legal-holds",
        json={
            "scope": "investigation",
            "investigation_id": str(t.investigation_id),
            "reason": " Litigation ",
        },
        headers=csrf(c),
    )
    assert response.status_code == 201, response.text
    hold = response.json()
    assert hold["scope"] == "investigation" and hold["reason"] == "Litigation"
    assert hold["active"] is True and hold["protects_until"] is None
    assert hold["s3_sync"] == "pending" and hold["s3_synced_at"] is None
    assert hold["case_ref"].startswith("CASE-") and hold["placed_by"] == str(reg.user_id)
    assert captured.published == [("retention.sync_holds", {"org_id": str(t.org_id)})]
    placed = await _audit(t.org_id, "legal_hold.placed")
    assert placed == [
        {
            "scope": "investigation",
            "investigation_id": str(t.investigation_id),
            "case_ref": hold["case_ref"],
        }
    ]
    case = (await c.get(f"{API}/{t.org_id}/investigations/{t.investigation_id}")).json()
    assert case["legal_hold"] is True
    listed = (await c.get(f"{API}/{t.org_id}/investigations")).json()["items"]
    assert {i["id"]: i["legal_hold"] for i in listed}[str(t.investigation_id)] is True
    evidence = (await c.get(f"{API}/{t.org_id}/evidence/{evidence_id}")).json()
    assert evidence["legal_hold"] is True
    other = await seed_case(t, title="Not held")
    assert (await c.get(f"{API}/{t.org_id}/investigations/{other}")).json()["legal_hold"] is False


async def test_an_org_hold_covers_every_case_without_s3_calls(captured: Captured) -> None:
    reg, t = await owner_tenant()
    c = reg.client
    response = await c.post(
        f"{API}/{t.org_id}/legal-holds",
        json={"scope": "org", "reason": "Regulator"},
        headers=csrf(c),
    )
    assert response.status_code == 201, response.text
    assert response.json()["s3_sync"] == "synced"  # nothing to mirror for an org hold
    assert captured.published == []
    other = await seed_case(t, title="Any case")
    assert (await c.get(f"{API}/{t.org_id}/investigations/{other}")).json()["legal_hold"] is True


async def test_scope_and_target_are_validated(captured: Captured) -> None:
    reg, t = await owner_tenant()
    c = reg.client
    url = f"{API}/{t.org_id}/legal-holds"
    no_case = await c.post(url, json={"scope": "investigation", "reason": "x"}, headers=csrf(c))
    assert no_case.status_code == 422 and no_case.json()["error"]["code"] == "hold_scope_invalid"
    org_with_case = await c.post(
        url,
        json={"scope": "org", "investigation_id": str(t.investigation_id), "reason": "x"},
        headers=csrf(c),
    )
    assert org_with_case.status_code == 422
    blank = await c.post(url, json={"scope": "org", "reason": "   "}, headers=csrf(c))
    assert blank.status_code == 422
    long = await c.post(url, json={"scope": "org", "reason": "x" * 501}, headers=csrf(c))
    assert long.status_code == 422
    unknown = await c.post(
        url,
        json={"scope": "investigation", "investigation_id": str(uuid.uuid4()), "reason": "x"},
        headers=csrf(c),
    )
    assert unknown.status_code == 404
    assert captured.published == []


async def test_release_once_keeps_protecting_for_the_delay(captured: Captured) -> None:
    reg, t = await owner_tenant()
    c = reg.client
    placed = await c.post(
        f"{API}/{t.org_id}/legal-holds",
        json={
            "scope": "investigation",
            "investigation_id": str(t.investigation_id),
            "reason": "Matter",
        },
        headers=csrf(c),
    )
    hold_id = placed.json()["id"]
    released = await c.post(
        f"{API}/{t.org_id}/legal-holds/{hold_id}/release",
        json={"reason": "Matter settled"},
        headers=csrf(c),
    )
    assert released.status_code == 200, released.text
    body = released.json()
    delay = timedelta(days=get_settings().retention_policy_delay_days)
    released_at = datetime.fromisoformat(body["released_at"])
    assert datetime.fromisoformat(body["protects_until"]) == released_at + delay
    assert body["active"] is True and body["release_reason"] == "Matter settled"
    assert body["released_by"] == str(reg.user_id)
    # Still protecting: the case stays flagged during the delay (RT1).
    case = (await c.get(f"{API}/{t.org_id}/investigations/{t.investigation_id}")).json()
    assert case["legal_hold"] is True
    again = await c.post(
        f"{API}/{t.org_id}/legal-holds/{hold_id}/release", json={"reason": "Twice"}, headers=csrf(c)
    )
    assert again.status_code == 409 and again.json()["error"]["code"] == "legal_hold_released"
    assert len(await _audit(t.org_id, "legal_hold.released")) == 1
    missing = await c.post(
        f"{API}/{t.org_id}/legal-holds/{uuid.uuid4()}/release",
        json={"reason": "x"},
        headers=csrf(c),
    )
    assert missing.status_code == 404


async def test_listing_filters_active_and_case(captured: Captured) -> None:
    reg, t = await owner_tenant()
    other = await seed_case(t, title="Second")
    # Released long ago (protection over), released recently (still protecting), active.
    old = await seed_released_hold(t, 30, investigation_id=t.investigation_id)
    recent = await seed_released_hold(t, 1, investigation_id=other)
    c = reg.client
    active = await c.post(
        f"{API}/{t.org_id}/legal-holds", json={"scope": "org", "reason": "Org"}, headers=csrf(c)
    )
    all_holds = (await c.get(f"{API}/{t.org_id}/legal-holds")).json()
    assert all_holds["total"] == 3
    by_id = {h["id"]: h for h in all_holds["items"]}
    assert by_id[str(old)]["active"] is False and by_id[str(recent)]["active"] is True
    protecting = (await c.get(f"{API}/{t.org_id}/legal-holds", params={"active_only": True})).json()
    assert {h["id"] for h in protecting["items"]} == {str(recent), active.json()["id"]}
    for_case = (
        await c.get(f"{API}/{t.org_id}/legal-holds", params={"investigation_id": str(other)})
    ).json()
    assert [h["id"] for h in for_case["items"]] == [str(recent)]


async def test_analysts_list_but_only_admins_place_or_release(captured: Captured) -> None:
    reg, t = await owner_tenant()
    email = unique_email("analyst")
    await add_member(t.org_id, await make_user(email), MemberRole.ANALYST)
    analyst = await login(email)
    assert (await analyst.get(f"{API}/{t.org_id}/legal-holds")).status_code == 200
    denied = await analyst.post(
        f"{API}/{t.org_id}/legal-holds", json={"scope": "org", "reason": "x"}, headers=csrf(analyst)
    )
    assert denied.status_code == 403
    assert reg.user_id
