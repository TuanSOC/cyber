"""`pnpm identity:admin bootstrap-owner --email <e> --org-name <n> --yes` (M11 phase 3).

Creates the initial organization (created_by = retention system user) and an owner invitation
(invited_by = retention system user), printing the single-use registration link:
`{PUBLIC_BASE_URL}/register#t=<token>` directly to stdout once.
"""

from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
import sys
import uuid

from sqlalchemy import select

from app.core.config import RETENTION_SYSTEM_USER_ID, get_settings
from app.core.tenancy import tenant_session
from app.modules.audit import service as audit
from app.modules.invitations.models import InvitationIndex, OrgInvitation
from app.modules.organizations import repository as repo_orgs
from app.modules.organizations.models import MemberRole, Organization
from app.modules.organizations.service import slugify
from app.modules.users import repository as users_repo


async def bootstrap_owner(email: str, org_name: str) -> tuple[int, str]:
    email_clean = email.strip().lower()
    org_name_clean = org_name.strip()

    # 1. Check existing user and find candidate orgs from invitation_index
    async with tenant_session(None, None) as session:
        existing_user = await users_repo.get_by_email(session, email_clean)
        if existing_user is not None:
            return 1, f"Error: user with email {email_clean} already exists. Invite them from an existing owner."

        stmt_candidates = select(InvitationIndex.organization_id).distinct()
        candidate_org_ids = (await session.execute(stmt_candidates)).scalars().all()

    # 2. Check candidate orgs under tenant session for matching name and existing owners
    existing_org_id = None
    for cand_id in candidate_org_ids:
        async with tenant_session(cand_id, RETENTION_SYSTEM_USER_ID) as session:
            org = (
                await session.execute(select(Organization).where(Organization.id == cand_id))
            ).scalar_one_or_none()
            if org and org.name.lower() == org_name_clean.lower():
                owner_count = await repo_orgs.count_owners(session, cand_id)
                if owner_count > 0:
                    return 1, f"Error: organization '{org_name_clean}' already exists and has an owner."
                existing_org_id = cand_id
                break

    org_id = existing_org_id or uuid.uuid4()
    new_org = existing_org_id is None
    slug = slugify(org_name_clean)

    # 3. Mutate under tenant session with RETENTION_SYSTEM_USER_ID
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    inv_id = uuid.uuid4()

    async with tenant_session(org_id, RETENTION_SYSTEM_USER_ID) as session:
        if new_org:
            org = Organization(
                id=org_id,
                name=org_name_clean,
                slug=slug,
                created_by=RETENTION_SYSTEM_USER_ID,
            )
            session.add(org)
            await session.flush()

        inv = OrgInvitation(
            id=inv_id,
            organization_id=org_id,
            email=email_clean,
            role=MemberRole.OWNER,
            token_hash=token_hash,
            invited_by=RETENTION_SYSTEM_USER_ID,
            expires_at=expires_at,
            resend_count=0,
        )
        session.add(inv)
        await session.flush()

        idx = InvitationIndex(
            invitation_id=inv_id,
            organization_id=org_id,
            token_hash=token_hash,
            expires_at=expires_at,
        )
        session.add(idx)

        audit.record(
            session,
            action="invitation.created",
            org_id=org_id,
            actor_id=RETENTION_SYSTEM_USER_ID,
            target_type="invitation",
            target_id=inv_id,
            details={"email": email_clean, "role": MemberRole.OWNER.value, "via": "operator"},
        )

    public_base = (get_settings().public_base_url or "http://localhost:8080").rstrip("/")
    link = f"{public_base}/register#t={token}"
    return 0, link


def run(args: argparse.Namespace) -> int:
    email = getattr(args, "email", None)
    org_name = getattr(args, "org_name", None)
    confirmed = getattr(args, "yes", False)

    if not email or not org_name:
        print("Usage: bootstrap-owner --email <email> --org-name <org-name> --yes", file=sys.stderr)
        return 2

    if not confirmed:
        print("Error: --yes confirmation flag required", file=sys.stderr)
        return 2

    code, message = asyncio.run(bootstrap_owner(email, org_name))
    if code != 0:
        print(message, file=sys.stderr)
        return code

    print(f"Owner invitation created for {email}:")
    print(message)
    return 0
