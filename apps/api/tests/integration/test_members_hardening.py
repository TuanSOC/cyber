import asyncio
import uuid

import pytest
from sqlalchemy import update

from app.core.deps import CurrentUser
from app.core.errors import Conflict
from app.core.rbac import OrgContext
from app.core.tenancy import tenant_session
from app.modules.organizations import members, repository
from app.modules.organizations.models import MemberRole
from app.modules.users.models import User
from tests.factories import csrf, make_user, register, unique_email
from tests.integration.test_orgs_members import org_with_roles


async def test_member_mutations_wait_for_the_org_lock() -> None:
    """Hold the org lock in a test transaction: both demotions must block, then serialize."""
    org = await org_with_roles()
    owner, admin = org.clients["owner"], org.clients["admin"]
    base = f"/api/v1/orgs/{org.org_id}/members"
    await owner.patch(
        f"{base}/{org.member_ids['admin']}", json={"role": "owner"}, headers=csrf(owner)
    )

    async with tenant_session(org.org_id, None) as held:
        await repository.lock_org(held, org.org_id)
        tasks = [
            asyncio.create_task(
                owner.patch(
                    f"{base}/{org.member_ids['admin']}",
                    json={"role": "viewer"},
                    headers=csrf(owner),
                )
            ),
            asyncio.create_task(
                admin.patch(
                    f"{base}/{org.member_ids['owner']}",
                    json={"role": "viewer"},
                    headers=csrf(admin),
                )
            ),
        ]
        await asyncio.sleep(0.5)
        assert not any(t.done() for t in tasks), "member mutation did not wait for the org lock"
    results = await asyncio.gather(*tasks)

    # The loser re-reads its own role after the lock: already demoted -> 403.
    assert sorted(r.status_code for r in results) == [200, 403], [r.text for r in results]
    winner = owner if results[0].status_code == 200 else admin
    roles = [m["role"] for m in (await winner.get(base)).json()["items"]]
    assert roles.count("owner") == 1


async def test_last_owner_guard() -> None:
    reg = await register()
    async with tenant_session(reg.org_id, reg.user_id) as session:
        owner_row = await repository.find_member_by_user(session, reg.org_id, reg.user_id)
        assert owner_row is not None
        user = CurrentUser(
            id=reg.user_id,
            email=reg.email,
            display_name="o",
            jti="x",
            family_id=uuid.uuid4(),
            token_expires_at=owner_row.created_at,
        )
        ctx = OrgContext(org_id=reg.org_id, user=user, role=MemberRole.OWNER, session=session)
        await repository.lock_org(session, reg.org_id)
        with pytest.raises(Conflict) as exc:
            await members.ensure_other_owner_remains(ctx, owner_row)
    assert exc.value.code == "last_owner"


async def test_member_ids_from_another_org_are_404() -> None:
    a = await org_with_roles()
    b = await org_with_roles()
    admin_a = a.clients["admin"]
    foreign = b.member_ids["viewer"]
    url = f"/api/v1/orgs/{a.org_id}/members/{foreign}"
    patch = await admin_a.patch(url, json={"role": "analyst"}, headers=csrf(admin_a))
    delete = await admin_a.delete(url, headers=csrf(admin_a))
    assert (patch.status_code, delete.status_code) == (404, 404)
    still_there = (await b.clients["owner"].get(f"/api/v1/orgs/{b.org_id}/members")).json()
    assert any(m["id"] == str(foreign) and m["role"] == "viewer" for m in still_there["items"])


async def test_same_role_patch_is_a_noop_without_audit() -> None:
    org = await org_with_roles()
    admin = org.clients["admin"]
    response = await admin.patch(
        f"/api/v1/orgs/{org.org_id}/members/{org.member_ids['viewer']}",
        json={"role": "viewer"},
        headers=csrf(admin),
    )
    assert (response.status_code, response.json()["role"]) == (200, "viewer")
    logs = (
        await admin.get(f"/api/v1/orgs/{org.org_id}/audit-logs?action=member.role_changed")
    ).json()
    assert logs["total"] == 0


async def test_cannot_remove_self() -> None:
    org = await org_with_roles()
    admin = org.clients["admin"]
    response = await admin.delete(
        f"/api/v1/orgs/{org.org_id}/members/{org.member_ids['admin']}", headers=csrf(admin)
    )
    assert (response.status_code, response.json()["error"]["code"]) == (403, "cannot_modify_self")


async def test_inactive_user_cannot_be_added() -> None:
    org = await org_with_roles()
    email = unique_email("gone")
    user_id = await make_user(email)
    async with tenant_session(None, None) as s:
        await s.execute(update(User).where(User.id == user_id).values(is_active=False))
    admin = org.clients["admin"]
    response = await admin.post(
        f"/api/v1/orgs/{org.org_id}/members",
        json={"email": email, "role": "viewer"},
        headers=csrf(admin),
    )
    assert (response.status_code, response.json()["error"]["code"]) == (404, "user_not_found")


async def test_list_endpoints_cap_offset_and_limit() -> None:
    reg = await register()
    for url in (
        "/api/v1/orgs",
        f"/api/v1/orgs/{reg.org_id}/members",
        f"/api/v1/orgs/{reg.org_id}/audit-logs",
    ):
        assert (await reg.client.get(url, params={"offset": 10**20})).status_code == 422
        assert (await reg.client.get(url, params={"limit": 0})).status_code == 422


@pytest.mark.parametrize(
    "params",
    [
        {"from": "2026-01-01T00:00:00"},  # naive datetime
        {"from": "2026-02-01T00:00:00Z", "to": "2026-01-01T00:00:00Z"},  # inverted range
    ],
)
async def test_audit_time_filters_validate(params: dict[str, str]) -> None:
    reg = await register()
    response = await reg.client.get(f"/api/v1/orgs/{reg.org_id}/audit-logs", params=params)
    assert (response.status_code, response.json()["error"]["code"]) == (422, "validation_error")


async def test_org_creation_is_rate_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("app.modules.organizations.service.ORG_CREATE_LIMIT_PER_HOUR", 2)
    reg = await register()
    statuses = [
        (
            await reg.client.post(
                "/api/v1/orgs", json={"name": f"Org {i}"}, headers=csrf(reg.client)
            )
        ).status_code
        for i in range(3)
    ]
    assert statuses == [201, 201, 429]


async def test_concurrent_duplicate_adds_never_500() -> None:
    """Exactly one 201, the other a clean 409; one membership row."""
    org = await org_with_roles()
    email = unique_email("dup")
    await make_user(email)
    admin, owner = org.clients["admin"], org.clients["owner"]
    url = f"/api/v1/orgs/{org.org_id}/members"
    results = await asyncio.gather(
        admin.post(url, json={"email": email, "role": "viewer"}, headers=csrf(admin)),
        owner.post(url, json={"email": email, "role": "analyst"}, headers=csrf(owner)),
    )
    assert sorted(r.status_code for r in results) == [201, 409]
    page = (await owner.get(url)).json()
    assert [m["email"] for m in page["items"]].count(email) == 1
