"""M11 test helpers (phase 1, FROZEN): sessions with a chosen `amr` / step-up age, a known TOTP
secret, invitations, domains and IdP configs, service accounts with API keys, outbox readers
and a Mailpit REST client. Real rows through the app role (RLS applies), test values only.
"""

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from httpx import AsyncClient
from sqlalchemy import Float, bindparam, select, text, update

from app.core.cookies import ACCESS_COOKIE
from app.core.security import decode_access_token, hash_token
from app.core.tenancy import tenant_session
from app.modules.api_keys.auth import new_key, secret_hash
from app.modules.api_keys.models import ApiKey
from app.modules.identity.models import (
    OrgDomain,
    OrgIdpConfig,
    SsoDomainIndex,
    UserSession,
)
from app.modules.invitations.models import InvitationIndex, OrgInvitation
from app.modules.mail.models import EmailOutbox
from app.modules.organizations.models import MemberRole, OrganizationMember
from app.modules.users.models import User, UserKind

# A fixed, test-only TOTP secret (RFC 6238 Appendix B's ASCII "12345678901234567890").
TOTP_SECRET = base64.b32encode(b"12345678901234567890").decode()

# The non-org M11 routes frozen as 501 stubs in phase 1 (method, path under /api/v1).
# Phase 3 moves out email verification and invitation inspect/accept.
# Phase 4 moves out password forgot/reset/change, sessions and events.
M11_NON_ORG_STUBS: frozenset[tuple[str, str]] = frozenset(
    {
        ("POST", "/auth/mfa/verify"),
        ("GET", "/auth/mfa"),
        ("POST", "/auth/mfa/totp/setup"),
        ("POST", "/auth/mfa/totp/confirm"),
        ("DELETE", "/auth/mfa/totp"),
        ("POST", "/auth/mfa/recovery-codes"),
        ("POST", "/auth/step-up"),
        ("POST", "/auth/sso/start"),
        ("GET", "/auth/sso/callback"),
    }
)
NON_ORG_STUB_PATHS: frozenset[str] = frozenset(path for _, path in M11_NON_ORG_STUBS)


# --- TOTP (test-side reference; the app's own verifier is phase 5) -------------------------


def totp_code(secret: str = TOTP_SECRET, at: float | None = None, *, step: int = 30) -> str:
    """RFC 6238 SHA-1, 6 digits."""
    counter = int((time.time() if at is None else at) // step)
    key = base64.b32decode(secret)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


# --- sessions --------------------------------------------------------------------------------


def session_id_of(client: AsyncClient) -> uuid.UUID:
    """The `sid` (= refresh family, `user_sessions.id`) of a signed-in test client."""
    token = client.cookies.get(ACCESS_COOKIE)
    assert token, "client is not signed in"
    return decode_access_token(token).family_id


async def get_session_row(family_id: uuid.UUID) -> UserSession | None:
    async with tenant_session(None, None) as session:
        return (
            await session.execute(select(UserSession).where(UserSession.id == family_id))
        ).scalar_one_or_none()


async def set_step_up(family_id: uuid.UUID, *, seconds_ago: float | None) -> None:
    """`step_up_at = now() - seconds_ago` (DB time), or NULL."""
    async with tenant_session(None, None) as session:
        if seconds_ago is None:
            await session.execute(
                update(UserSession).where(UserSession.id == family_id).values(step_up_at=None)
            )
            return
        await session.execute(
            text(
                "UPDATE user_sessions SET step_up_at = now() - make_interval(secs => :s) "
                "WHERE id = :id"
            ).bindparams(bindparam("s", type_=Float)),
            {"s": float(seconds_ago), "id": family_id},
        )


async def set_amr(family_id: uuid.UUID, amr: list[str]) -> None:
    """Rewrite the row's `amr` (the next refresh re-issues the token with it)."""
    async with tenant_session(None, None) as session:
        await session.execute(
            update(UserSession).where(UserSession.id == family_id).values(amr=amr)
        )


async def mark_email_verified(user_id: uuid.UUID) -> None:
    async with tenant_session(None, user_id) as session:
        await session.execute(
            text("UPDATE users SET email_verified_at = now() WHERE id = :id"), {"id": user_id}
        )


async def set_password_hash(user_id: uuid.UUID, password_hash: str) -> None:
    """E.g. `!sso` for an SSO-only user (RT5 timing class)."""
    async with tenant_session(None, user_id) as session:
        await session.execute(
            update(User).where(User.id == user_id).values(password_hash=password_hash)
        )


# --- invitations ----------------------------------------------------------------------------


@dataclass(frozen=True)
class SeededInvitation:
    id: uuid.UUID
    token: str


async def seed_invitation(
    org_id: uuid.UUID,
    invited_by: uuid.UUID,
    email: str,
    role: MemberRole = MemberRole.VIEWER,
    *,
    ttl: timedelta = timedelta(days=7),
    created_at: datetime | None = None,
) -> SeededInvitation:
    token = secrets.token_urlsafe(32)
    invitation_id = uuid.uuid4()
    base_time = created_at or datetime.now(UTC)
    expires_at = base_time + ttl
    kwargs = {"created_at": created_at} if created_at is not None else {}
    async with tenant_session(org_id, invited_by) as session:
        session.add(
            OrgInvitation(
                id=invitation_id,
                organization_id=org_id,
                email=email,
                role=role,
                token_hash=hash_token(token),
                invited_by=invited_by,
                expires_at=expires_at,
                **kwargs,
            )
        )
        await session.flush()
        session.add(
            InvitationIndex(
                invitation_id=invitation_id,
                organization_id=org_id,
                token_hash=hash_token(token),
                expires_at=expires_at,
            )
        )
    return SeededInvitation(id=invitation_id, token=token)


# --- SSO administration ---------------------------------------------------------------------


async def seed_domain(
    org_id: uuid.UUID, created_by: uuid.UUID, domain: str, *, verified: bool = False
) -> uuid.UUID:
    domain_id = uuid.uuid4()
    async with tenant_session(org_id, created_by) as session:
        session.add(
            OrgDomain(
                id=domain_id,
                organization_id=org_id,
                domain=domain,
                challenge=secrets.token_urlsafe(32),
                status="verified" if verified else "pending",
                method="operator" if verified else None,
                verified_at=datetime.now(UTC) if verified else None,
                created_by=created_by,
            )
        )
    return domain_id


async def seed_idp_config(
    org_id: uuid.UUID,
    created_by: uuid.UUID,
    *,
    issuer: str = "https://idp-mock.test",
    client_id: str = "cyberlab-test-client",
    domain: str | None = None,
    enabled: bool = True,
    jit: bool = False,
) -> uuid.UUID:
    """An IdP config without a sealed secret (phase 7 seals one); with `domain`, a verified
    domain and its `sso_domain_index` row."""
    config_id = uuid.uuid4()
    async with tenant_session(org_id, created_by) as session:
        session.add(
            OrgIdpConfig(
                id=config_id,
                organization_id=org_id,
                issuer=issuer,
                client_id=client_id,
                enabled=enabled,
                jit_enabled=jit,
                created_by=created_by,
            )
        )
        await session.flush()
        if domain is not None:
            session.add(
                SsoDomainIndex(
                    domain=domain, organization_id=org_id, idp_config_id=config_id, enabled=enabled
                )
            )
    if domain is not None:
        await seed_domain(org_id, created_by, domain, verified=True)
    return config_id


# --- service accounts and API keys ----------------------------------------------------------


@dataclass(frozen=True)
class SeededKey:
    key: str  # `clk_…`, test only
    key_id: uuid.UUID
    service_user_id: uuid.UUID
    public_id: str


async def seed_api_key(
    org_id: uuid.UUID,
    created_by: uuid.UUID,
    *,
    role: str = "analyst",
    scopes: tuple[str, ...] = ("investigation.read", "evidence.read"),
    days: int = 30,
    name: str = "CI key",
) -> SeededKey:
    key, parsed = new_key()
    key_id, user_id = uuid.uuid4(), uuid.uuid4()
    async with tenant_session(org_id, created_by) as session:
        session.add(
            User(
                id=user_id,
                email=f"svc-{user_id}@service.invalid",
                password_hash="!service",
                display_name=name,
                kind=UserKind.SERVICE.value,
            )
        )
        await session.flush()
        session.add(
            OrganizationMember(organization_id=org_id, user_id=user_id, role=MemberRole(role))
        )
        session.add(
            ApiKey(
                id=key_id,
                organization_id=org_id,
                service_user_id=user_id,
                name=name,
                public_id=parsed.public_id,
                secret_hash=secret_hash(parsed.secret),
                role=role,
                scopes=list(scopes),
                created_by=created_by,
                expires_at=datetime.now(UTC) + timedelta(days=days),
            )
        )
    return SeededKey(key=key, key_id=key_id, service_user_id=user_id, public_id=parsed.public_id)


def bearer(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


# --- mail -----------------------------------------------------------------------------------


async def outbox_rows(to: str | None = None) -> list[EmailOutbox]:
    async with tenant_session(None, None) as session:
        stmt = select(EmailOutbox).order_by(EmailOutbox.created_at)
        if to is not None:
            stmt = stmt.where(EmailOutbox.to_email == to)
        return list((await session.execute(stmt)).scalars())


class MailpitClient:
    """The test Mailpit's REST API (`mailpit-test`, network `mail`; api-test only, RT24)."""

    def __init__(self, base_url: str | None = None) -> None:
        self.base_url = base_url or os.environ.get("MAILPIT_TEST_URL", "http://mailpit-test:8025")

    async def messages(self, to: str | None = None) -> list[dict[str, Any]]:
        params = {"query": f"to:{to}"} if to else None
        path = "/api/v1/search" if to else "/api/v1/messages"
        async with httpx.AsyncClient(base_url=self.base_url, timeout=10) as client:
            response = await client.get(path, params=params)
            response.raise_for_status()
            return list(response.json().get("messages", []))

    async def message_text(self, message_id: str) -> str:
        async with httpx.AsyncClient(base_url=self.base_url, timeout=10) as client:
            response = await client.get(f"/api/v1/message/{message_id}")
            response.raise_for_status()
            return str(response.json().get("Text", ""))

    async def delete_all(self) -> None:
        async with httpx.AsyncClient(base_url=self.base_url, timeout=10) as client:
            (await client.delete("/api/v1/messages")).raise_for_status()
