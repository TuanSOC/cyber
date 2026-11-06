"""Registration, login and the current-user view.

Commit rule: the failed-login event is committed (tenant_session block left) before the
401 is raised. Session/token lifecycle lives in sessions.py.
"""

import uuid
from dataclasses import dataclass, field

from sqlalchemy.exc import IntegrityError
from starlette.requests import HTTPConnection

from app.core import rate_limit
from app.core.client_ip import ip_key
from app.core.config import get_settings
from app.core.cookies import IssuedTokens
from app.core.errors import Conflict, Unauthorized
from app.core.security import hash_password_async, password_needs_rehash, verify_password_async
from app.core.tenancy import tenant_session
from app.modules.audit import service as audit
from app.modules.auth import sessions
from app.modules.auth.events import record_auth_event
from app.modules.auth.models import AuthEventType
from app.modules.auth.schemas import LoginIn, MembershipOut, MeOut, RegisterIn
from app.modules.identity.errors import RegistrationClosed
from app.modules.invitations import service as invitations
from app.modules.organizations import repository as orgs
from app.modules.organizations.models import MemberRole, Organization, OrganizationMember
from app.modules.organizations.service import slugify
from app.modules.users import repository as users
from app.modules.users.models import User
from app.modules.users.schemas import UserOut

LOGIN_FAILURE_WINDOW_S = 15 * 60
EMAIL_UNIQUE_CONSTRAINT = "uq_users_email"


@dataclass(frozen=True)
class MfaChallenge:
    """M11 phase 5: the password was right and the account has an active factor. The router
    answers `202 MfaChallengeOut`, sets `cl_mfa` (= `challenge_id`) and `cl_csrf`; no session
    exists yet. Phase 1 never returns one (no factor can be enrolled before phase 5)."""

    challenge_id: str = field(repr=False)
    csrf_token: str = field(repr=False)
    methods: tuple[str, ...]


LoginResult = tuple[MeOut, IssuedTokens] | MfaChallenge


async def me(user_id: uuid.UUID) -> MeOut:
    async with tenant_session(None, user_id) as session:
        user = await users.get_active(session, user_id)
        if user is None:
            raise Unauthorized(code="invalid_token")
        memberships = await orgs.list_memberships(session, user_id)
    return MeOut(
        user=UserOut.model_validate(user),
        memberships=[
            MembershipOut(organization_id=org_id, organization_name=name, role=role)
            for org_id, name, role in memberships
        ],
    )


async def register(data: RegisterIn, request: HTTPConnection) -> tuple[MeOut, IssuedTokens]:
    settings = get_settings()
    await rate_limit.hit(
        f"register:ip:{ip_key(request)}", settings.rate_limit_register_per_ip_per_10min, 600
    )
    # M11: `invite_only` refuses an uninvited registration before any lookup (no bootstrap
    # rule, RT12: the first owner comes from `identity:admin bootstrap-owner`).
    if data.invitation_token is None and settings.registration_mode == "invite_only":
        raise RegistrationClosed()
    password_hash = await hash_password_async(data.password)  # before opening a transaction
    if data.invitation_token is not None:
        # Phase 3: joins the invitation's org (no new org), email verified by the token.
        invited_user, invited_tokens = await invitations.register_with_invitation(
            data, password_hash, request
        )
        return await me(invited_user), invited_tokens
    organization_name = data.organization_name
    if organization_name is None:  # RegisterIn guarantees it without an invitation
        raise RegistrationClosed()
    user_id, org_id = uuid.uuid4(), uuid.uuid4()
    try:
        async with tenant_session(org_id, user_id) as session:
            session.add(
                User(
                    id=user_id,
                    email=str(data.email),
                    password_hash=password_hash,
                    display_name=data.display_name,
                )
            )
            await session.flush()
            session.add(
                Organization(
                    id=org_id,
                    name=organization_name,
                    slug=slugify(organization_name),
                    created_by=user_id,
                )
            )
            await session.flush()
            session.add(
                OrganizationMember(organization_id=org_id, user_id=user_id, role=MemberRole.OWNER)
            )
            audit.record(
                session,
                action="org.created",
                org_id=org_id,
                actor_id=user_id,
                target_type="organization",
                target_id=org_id,
                details={"name": organization_name},
                request=request,
            )
            record_auth_event(
                session,
                AuthEventType.REGISTER,
                request=request,
                user_id=user_id,
                email=str(data.email),
            )
            issued = await sessions.start_session(session, user_id, request)
    except IntegrityError as exc:
        if EMAIL_UNIQUE_CONSTRAINT not in str(exc.orig):
            raise
        raise Conflict("Unable to register with these details", code="registration_failed") from exc
    return await me(user_id), issued


async def login(data: LoginIn, request: HTTPConnection) -> LoginResult:
    """Password sign-in. M11: phase 5 returns an `MfaChallenge` instead of a session when the
    account has an active factor (the router answers 202)."""
    settings = get_settings()
    ip = ip_key(request)
    email = str(data.email).lower()
    failure_key = f"login:fail:{email}:{ip}"
    await rate_limit.hit(f"login:ip:{ip}", settings.rate_limit_login_per_ip_per_min, 60)
    # Reserve a failure slot up front (atomic); it is given back if the login succeeds.
    await rate_limit.hit(
        failure_key, settings.rate_limit_login_failures_per_15min, LOGIN_FAILURE_WINDOW_S
    )

    async with tenant_session(None, None) as session:
        user = await users.get_by_email(session, email)
    valid = await verify_password_async(user.password_hash if user else None, data.password)

    if user is None or not valid or not user.is_active:
        async with tenant_session(None, None) as session:
            record_auth_event(
                session,
                AuthEventType.LOGIN_FAILURE,
                request=request,
                user_id=user.id if user else None,
                email=email,
            )
        # Event committed above; now it is safe to fail the request.
        raise Unauthorized("Invalid email or password", code="invalid_credentials")

    await rate_limit.release(failure_key)
    new_hash = (
        await hash_password_async(data.password)
        if password_needs_rehash(user.password_hash)
        else None
    )
    async with tenant_session(None, user.id) as session:
        if new_hash is not None:
            db_user = await users.get_active(session, user.id)
            if db_user is not None:
                db_user.password_hash = new_hash
        issued = await sessions.start_session(session, user.id, request)
        record_auth_event(
            session, AuthEventType.LOGIN_SUCCESS, request=request, user_id=user.id, email=email
        )
    return await me(user.id), issued
