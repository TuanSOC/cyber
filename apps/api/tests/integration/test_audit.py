import json

from tests.factories import csrf, register
from tests.integration.test_orgs_members import org_with_roles


async def test_audit_lists_only_own_org_newest_first_with_actor() -> None:
    org = await org_with_roles()
    other = await register(org_name="Other")
    await other.client.patch(
        f"/api/v1/orgs/{other.org_id}", json={"name": "Other 2"}, headers=csrf(other.client)
    )
    admin = org.clients["admin"]
    await admin.patch(f"/api/v1/orgs/{org.org_id}", json={"name": "Mine 2"}, headers=csrf(admin))

    page = (await admin.get(f"/api/v1/orgs/{org.org_id}/audit-logs")).json()
    actions = [i["action"] for i in page["items"]]
    assert actions[0] == "org.updated"
    assert actions[-1] == "org.created"
    assert page["total"] == len(page["items"])
    assert page["items"][0]["actor_email"] == org.emails["admin"]
    serialized = json.dumps(page)
    assert '"Other"' not in serialized and '"Other 2"' not in serialized


async def test_audit_filters_and_pagination() -> None:
    org = await org_with_roles()
    owner = org.clients["owner"]
    for n in range(3):
        await owner.patch(f"/api/v1/orgs/{org.org_id}", json={"name": f"N{n}"}, headers=csrf(owner))
    url = f"/api/v1/orgs/{org.org_id}/audit-logs"

    page = (await owner.get(url, params={"action": "org.updated", "limit": 2})).json()
    assert page["total"] == 3 and len(page["items"]) == 2
    rest = (await owner.get(url, params={"action": "org.updated", "limit": 2, "offset": 2})).json()
    assert len(rest["items"]) == 1
    names = [i["details"]["name"]["to"] for i in page["items"] + rest["items"]]
    assert names == ["N2", "N1", "N0"]

    too_big = await owner.get(url, params={"limit": 101})
    assert too_big.status_code == 422


async def test_audit_never_contains_secrets() -> None:
    reg = await register()
    page = (await reg.client.get(f"/api/v1/orgs/{reg.org_id}/audit-logs")).text
    assert "password" not in page.lower() and "token" not in page.lower()
