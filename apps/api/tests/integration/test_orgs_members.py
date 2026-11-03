import asyncio
import uuid
from dataclasses import dataclass

from httpx import AsyncClient

from app.modules.organizations.models import MemberRole
from tests.factories import add_member, csrf, login, make_user, register, unique_email


@dataclass
class Org:
    org_id: uuid.UUID
    clients: dict[str, AsyncClient]
    member_ids: dict[str, uuid.UUID]
    emails: dict[str, str]


async def org_with_roles() -> Org:
    owner = await register()
    clients = {"owner": owner.client}
    emails = {"owner": owner.email}
    for role in (MemberRole.ADMIN, MemberRole.ANALYST, MemberRole.VIEWER):
        email = unique_email(role.value)
        user_id = await make_user(email)
        await add_member(owner.org_id, user_id, role)
        clients[role.value] = await login(email)
        emails[role.value] = email
    members = (await owner.client.get(f"/api/v1/orgs/{owner.org_id}/members")).json()["items"]
    member_ids = {
        next(k for k, v in emails.items() if v == m["email"]): uuid.UUID(m["id"]) for m in members
    }
    return Org(org_id=owner.org_id, clients=clients, member_ids=member_ids, emails=emails)


async def test_list_and_create_my_orgs() -> None:
    reg = await register(org_name="First")
    created = await reg.client.post(
        "/api/v1/orgs", json={"name": "Second"}, headers=csrf(reg.client)
    )
    assert created.status_code == 201
    assert created.json()["role"] == "owner"
    mine = (await reg.client.get("/api/v1/orgs")).json()
    assert mine["total"] == 2
    assert [(o["name"], o["role"]) for o in mine["items"]] == [
        ("First", "owner"),
        ("Second", "owner"),
    ]


async def test_non_member_gets_404_for_every_org_route() -> None:
    a = await register()
    b = await register()
    routes = [
        ("GET", f"/api/v1/orgs/{a.org_id}", None),
        ("PATCH", f"/api/v1/orgs/{a.org_id}", {"name": "pwned"}),
        ("GET", f"/api/v1/orgs/{a.org_id}/members", None),
        ("POST", f"/api/v1/orgs/{a.org_id}/members", {"email": b.email, "role": "owner"}),
        ("GET", f"/api/v1/orgs/{a.org_id}/audit-logs", None),
        ("GET", f"/api/v1/orgs/{uuid.uuid4()}", None),
    ]
    for method, url, body in routes:
        response = await b.client.request(method, url, json=body, headers=csrf(b.client))
        assert response.status_code == 404, (method, url, response.text)
        assert response.json()["error"]["code"] == "not_found"


async def test_rename_org_is_audited() -> None:
    org = await org_with_roles()
    admin = org.clients["admin"]
    response = await admin.patch(
        f"/api/v1/orgs/{org.org_id}", json={"name": "Renamed"}, headers=csrf(admin)
    )
    assert (response.status_code, response.json()["name"]) == (200, "Renamed")
    logs = (await admin.get(f"/api/v1/orgs/{org.org_id}/audit-logs?action=org.updated")).json()
    assert logs["total"] == 1
    assert logs["items"][0]["details"]["name"] == {"from": "Acme IR", "to": "Renamed"}


async def test_add_member_by_email() -> None:
    org = await org_with_roles()
    admin = org.clients["admin"]
    email = unique_email("new")
    await make_user(email)
    url = f"/api/v1/orgs/{org.org_id}/members"
    added = await admin.post(url, json={"email": email, "role": "analyst"}, headers=csrf(admin))
    assert added.status_code == 201
    assert (added.json()["email"], added.json()["role"]) == (email, "analyst")

    again = await admin.post(url, json={"email": email, "role": "viewer"}, headers=csrf(admin))
    assert (again.status_code, again.json()["error"]["code"]) == (409, "already_member")
    unknown = await admin.post(
        url, json={"email": "ghost@example.com", "role": "viewer"}, headers=csrf(admin)
    )
    assert (unknown.status_code, unknown.json()["error"]["code"]) == (404, "user_not_found")


async def test_only_owners_touch_the_owner_role() -> None:
    org = await org_with_roles()
    admin, owner = org.clients["admin"], org.clients["owner"]
    base = f"/api/v1/orgs/{org.org_id}/members"
    email = unique_email("cand")
    await make_user(email)

    grant = await admin.post(base, json={"email": email, "role": "owner"}, headers=csrf(admin))
    assert grant.status_code == 403
    demote_owner = await admin.patch(
        f"{base}/{org.member_ids['owner']}", json={"role": "viewer"}, headers=csrf(admin)
    )
    assert demote_owner.status_code == 403
    remove_owner = await admin.delete(f"{base}/{org.member_ids['owner']}", headers=csrf(admin))
    assert remove_owner.status_code == 403

    promote = await owner.patch(
        f"{base}/{org.member_ids['admin']}", json={"role": "owner"}, headers=csrf(owner)
    )
    assert (promote.status_code, promote.json()["role"]) == (200, "owner")


async def test_members_cannot_change_their_own_membership() -> None:
    org = await org_with_roles()
    owner = org.clients["owner"]
    response = await owner.patch(
        f"/api/v1/orgs/{org.org_id}/members/{org.member_ids['owner']}",
        json={"role": "viewer"},
        headers=csrf(owner),
    )
    assert (response.status_code, response.json()["error"]["code"]) == (403, "cannot_modify_self")


async def test_removed_member_loses_access() -> None:
    org = await org_with_roles()
    admin, analyst = org.clients["admin"], org.clients["analyst"]
    response = await admin.delete(
        f"/api/v1/orgs/{org.org_id}/members/{org.member_ids['analyst']}", headers=csrf(admin)
    )
    assert response.status_code == 204
    assert (await analyst.get(f"/api/v1/orgs/{org.org_id}")).status_code == 404


async def test_concurrent_owner_demotions_keep_one_owner() -> None:
    org = await org_with_roles()
    owner, admin = org.clients["owner"], org.clients["admin"]
    base = f"/api/v1/orgs/{org.org_id}/members"
    promote = await owner.patch(
        f"{base}/{org.member_ids['admin']}", json={"role": "owner"}, headers=csrf(owner)
    )
    assert promote.status_code == 200
    # Two owners demote each other at the same time: exactly one may win.
    results = await asyncio.gather(
        owner.patch(
            f"{base}/{org.member_ids['admin']}", json={"role": "viewer"}, headers=csrf(owner)
        ),
        admin.patch(
            f"{base}/{org.member_ids['owner']}", json={"role": "viewer"}, headers=csrf(admin)
        ),
    )
    statuses = sorted(r.status_code for r in results)
    # Overlapping: both pass require(), the org lock serializes them -> 409 for the loser.
    # Not overlapping: the loser was already demoted to viewer -> 403.
    assert statuses in ([200, 403], [200, 409]), [r.text for r in results]
    winner = owner if results[0].status_code == 200 else admin
    members = (await winner.get(base)).json()["items"]
    assert [m["role"] for m in members].count("owner") == 1
