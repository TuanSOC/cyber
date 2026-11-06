"""M11 RT1: every in-service permission check reads `OrgContext.permissions` (the role's
permissions, or role ∩ scopes for an API key). Reading `ROLE_PERMISSIONS[...]` outside
`core/rbac.py` would let a key scoped to `investigation.read` pass its role's other checks."""

import re
from pathlib import Path

from app.core.rbac import ROLE_PERMISSIONS, OrgContext, Permission, effective_permissions
from app.modules.organizations.models import MemberRole

APP = Path(__file__).resolve().parents[2] / "app"
READ = re.compile(r"ROLE_PERMISSIONS\s*\[")


def test_no_role_permission_reads_outside_rbac() -> None:
    offenders = [
        f"{path.relative_to(APP).as_posix()}:{n}"
        for path in APP.rglob("*.py")
        if path.relative_to(APP).as_posix() != "core/rbac.py"
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if READ.search(line)
    ]
    assert offenders == [], offenders


def test_only_owners_manage_security() -> None:
    holders = {
        role for role, perms in ROLE_PERMISSIONS.items() if Permission.SECURITY_MANAGE in perms
    }
    assert holders == {MemberRole.OWNER}
    assert ROLE_PERMISSIONS[MemberRole.OWNER] - ROLE_PERMISSIONS[MemberRole.ADMIN] == {
        Permission.SECURITY_MANAGE
    }


def test_effective_permissions_intersect_role_and_scopes() -> None:
    assert effective_permissions(MemberRole.ANALYST, None) == ROLE_PERMISSIONS[MemberRole.ANALYST]
    scoped = effective_permissions(MemberRole.ANALYST, frozenset({"investigation.read"}))
    assert scoped == {Permission.INVESTIGATION_READ}
    # A scope the role does not hold grants nothing.
    assert effective_permissions(MemberRole.VIEWER, frozenset({"evidence.write"})) == frozenset()


def test_org_context_defaults_to_the_role_permissions() -> None:
    ctx = OrgContext(
        org_id=None,  # type: ignore[arg-type]
        user=None,  # type: ignore[arg-type]
        role=MemberRole.VIEWER,
        session=None,  # type: ignore[arg-type]
    )
    assert ctx.permissions == ROLE_PERMISSIONS[MemberRole.VIEWER]
    keyed = OrgContext(
        org_id=None,  # type: ignore[arg-type]
        user=None,  # type: ignore[arg-type]
        role=MemberRole.ANALYST,
        session=None,  # type: ignore[arg-type]
        permissions=frozenset(),
    )
    assert keyed.permissions == frozenset()
    assert not keyed.can(Permission.ORG_READ)
