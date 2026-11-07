import asyncio
import uuid

import pytest
from sqlalchemy import update

from app.core.deps import CurrentUser
from app.core.errors import Conflict
from app.core.rbac import OrgContext
from app.core.tenancy import tenant_session
from app.modules.organizations import members, repository
from app.modules.organizations.models import MemberRole, OrganizationMember
from app.modules.users.models import User, UserKind
from tests.factories import csrf, make_user, register, unique_email
from tests.identity_helpers import seed_api_key, session_id_of, set_step_up
from tests.integration.test_orgs_members import org_with_roles


async def test_member_mutations_wait_for_the_org_lock() -> None:
    """Hold the org lock in a test transaction: both demotions must block, then serialize."""
    org = await org_with_roles()
    owner, admin = org.clients["owner"], org.clients["admin"]
    base = f"/api/v1/orgs/{org.org_id}/members"
    await set_step_up(session_id_of(owner), seconds_ago=0)
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
    admin = org.clients["admin"]
    response = await admin.post(
        f"/api/v1/orgs/{org.org_id}/members",
        json={"email": "inactive@example.com", "role": "viewer"},
        headers=csrf(admin),
    )
    assert response.status_code == 410
    assert response.json()["error"]["code"] == "members_direct_add_removed"


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


async def test_direct_add_is_decommissioned_answers_410() -> None:
    """POST /orgs/{org}/members is permanently replaced by invitations and answers 410."""
    org = await org_with_roles()
    admin = org.clients["admin"]
    url = f"/api/v1/orgs/{org.org_id}/members"
    resp = await admin.post(
        url,
        json={"email": "candidate@example.com", "role": "analyst"},
        headers=csrf(admin),
    )
    assert resp.status_code == 410
    assert resp.json()["error"]["code"] == "members_direct_add_removed"


async def test_member_elevation_and_removal_require_step_up() -> None:
    org = await org_with_roles()
    owner = org.clients["owner"]
    viewer_id = org.member_ids["viewer"]
    base = f"/api/v1/orgs/{org.org_id}/members"

    # 1. Elevate to admin without step-up -> 403 step_up_required
    elevate_resp = await owner.patch(
        f"{base}/{viewer_id}",
        json={"role": "admin"},
        headers=csrf(owner),
    )
    assert elevate_resp.status_code == 403
    assert elevate_resp.json()["error"]["code"] == "step_up_required"

    # 2. Elevate with step-up succeeds
    await set_step_up(session_id_of(owner), seconds_ago=0)
    elevate_ok = await owner.patch(
        f"{base}/{viewer_id}",
        json={"role": "admin"},
        headers=csrf(owner),
    )
    assert elevate_ok.status_code == 200
    assert elevate_ok.json()["role"] == "admin"

    # 3. Remove without step-up -> 403 step_up_required
    await set_step_up(session_id_of(owner), seconds_ago=None)
    remove_resp = await owner.delete(
        f"{base}/{viewer_id}",
        headers=csrf(owner),
    )
    assert remove_resp.status_code == 403
    assert remove_resp.json()["error"]["code"] == "step_up_required"

    # 4. Remove with step-up succeeds
    await set_step_up(session_id_of(owner), seconds_ago=0)
    remove_ok = await owner.delete(
        f"{base}/{viewer_id}",
        headers=csrf(owner),
    )
    assert remove_ok.status_code == 204


async def test_service_accounts_refused_by_members_routes() -> None:
    """RT14: Service accounts cannot be modified or removed through members routes."""
    org = await org_with_roles()
    owner = org.clients["owner"]
    await set_step_up(session_id_of(owner), seconds_ago=0)

    # Seed a service account with API key
    seeded = await seed_api_key(org.org_id, org.user_ids["owner"])
    # Look up member_id for service account
    members_page = (await owner.get(f"/api/v1/orgs/{org.org_id}/members")).json()
    svc_member = next(m for m in members_page["items"] if m["user_id"] == str(seeded.service_user_id))
    svc_member_id = svc_member["id"]

    base = f"/api/v1/orgs/{org.org_id}/members/{svc_member_id}"

    # Try modifying service account role -> 409 service_account_member
    patch_resp = await owner.patch(
        base,
        json={"role": "viewer"},
        headers=csrf(owner),
    )
    assert patch_resp.status_code == 409
    assert patch_resp.json()["error"]["code"] == "service_account_member"

    # Try removing service account through members -> 409 service_account_member
    del_resp = await owner.delete(base, headers=csrf(owner))
    assert del_resp.status_code == 409
    assert del_resp.json()["error"]["code"] == "service_account_member"


async def test_count_owners_counts_human_members_only() -> None:
    """RT14: repo.count_owners ignores service accounts even if assigned owner role."""
    reg = await register()
    async with tenant_session(reg.org_id, reg.user_id) as session:
        human_owners = await repository.count_owners(session, reg.org_id)
        assert human_owners == 1

        # Add a service account with OWNER role directly
        svc_user_id = uuid.uuid4()
        session.add(
            User(
                id=svc_user_id,
                email="svc_owner@service.invalid",
                password_hash="!svc",
                display_name="Service Owner",
                kind="service",
            )
        )
        await session.flush()
        session.add(
            OrganizationMember(
                organization_id=reg.org_id,
                user_id=svc_user_id,
                role=MemberRole.OWNER,
            )
        )
        await session.flush()

        # count_owners must STILL be 1 (human owner only)
        assert await repository.count_owners(session, reg.org_id) == 1
