"""Minimal real-row seeding for schema-level tests (full factories arrive in phase 3)."""

import uuid
from dataclasses import dataclass

from app.core.tenancy import tenant_session
from app.modules.investigations.models import Investigation, Severity
from app.modules.organizations.models import MemberRole, Organization, OrganizationMember
from app.modules.users.models import User


@dataclass(frozen=True)
class Tenant:
    org_id: uuid.UUID
    owner_id: uuid.UUID
    investigation_id: uuid.UUID


async def seed_user(email: str) -> uuid.UUID:
    async with tenant_session(None, None) as s:
        user = User(email=email, password_hash="x", display_name=email.split("@")[0])
        s.add(user)
    return user.id


async def seed_tenant(name: str) -> Tenant:
    owner_id = await seed_user(f"owner@{name}.test")
    org_id = uuid.uuid4()
    async with tenant_session(org_id, owner_id) as s:
        s.add(Organization(id=org_id, name=name, slug=name, created_by=owner_id))
        await s.flush()
        s.add(OrganizationMember(organization_id=org_id, user_id=owner_id, role=MemberRole.OWNER))
        investigation = Investigation(
            organization_id=org_id,
            case_number=1,
            title=f"{name} case",
            severity=Severity.HIGH,
            created_by=owner_id,
        )
        s.add(investigation)
    return Tenant(org_id=org_id, owner_id=owner_id, investigation_id=investigation.id)
