"""Role x permission matrix against real endpoints (one representative route per permission)."""

import pytest

from app.core.rbac import ROLE_PERMISSIONS, Permission
from app.modules.organizations.models import MemberRole
from tests.factories import csrf, make_user, unique_email
from tests.integration.test_orgs_members import Org, org_with_roles

# permission -> (method, path suffix, json body factory). Bodies are valid so 2xx is possible.
ENDPOINTS: dict[Permission, tuple[str, str]] = {
    Permission.ORG_READ: ("GET", ""),
    Permission.ORG_UPDATE: ("PATCH", ""),
    Permission.MEMBERS_READ: ("GET", "/members"),
    Permission.MEMBERS_MANAGE: ("POST", "/members"),
    Permission.AUDIT_READ: ("GET", "/audit-logs"),
}


async def _call(org: Org, role: MemberRole, permission: Permission) -> int:
    method, suffix = ENDPOINTS[permission]
    client = org.clients[role.value]
    body: dict[str, str] | None = None
    if permission is Permission.ORG_UPDATE:
        body = {"name": f"Renamed by {role.value}"}
    elif permission is Permission.MEMBERS_MANAGE:
        email = unique_email("matrix")
        await make_user(email)
        body = {"email": email, "role": "viewer"}
    response = await client.request(
        method, f"/api/v1/orgs/{org.org_id}{suffix}", json=body, headers=csrf(client)
    )
    return response.status_code


@pytest.mark.parametrize("role", list(MemberRole))
async def test_role_permission_matrix(role: MemberRole) -> None:
    org = await org_with_roles()
    for permission in ENDPOINTS:
        status = await _call(org, role, permission)
        allowed = permission in ROLE_PERMISSIONS[role]
        assert (200 <= status < 300) == allowed, (role, permission, status)
        if not allowed:
            assert status == 403, (role, permission, status)


def test_matrix_matches_spec() -> None:
    """Pin the permission table from the phase 4 plan."""
    read = {"org.read", "members.read", "investigation.read", "evidence.read"}
    analyst = read | {"investigation.write", "evidence.write"}
    admin = analyst | {"org.update", "members.manage", "audit.read", "integrations.manage"}
    assert {p.value for p in ROLE_PERMISSIONS[MemberRole.VIEWER]} == read
    assert {p.value for p in ROLE_PERMISSIONS[MemberRole.ANALYST]} == analyst
    assert {p.value for p in ROLE_PERMISSIONS[MemberRole.ADMIN]} == admin
    # M11: `security.manage` (SSO, domains, the security policy, API keys) is the owners' only.
    assert {p.value for p in ROLE_PERMISSIONS[MemberRole.OWNER]} == admin | {"security.manage"}
