"""Password recovery and change service (M11 phase 4)."""

from __future__ import annotations

from datetime import timedelta
import hashlib
import logging
import secrets

from fastapi import BackgroundTasks
from sqlalchemy import func, select, update
from starlette.requests import HTTPConnection, Request

from app.core import rate_limit
from app.core.client_ip import client_ip, ip_key, user_agent
from app.core.deps import CurrentUser
from app.core.errors import Conflict, NotFound, Unauthorized
from app.core.security import hash_password_async, verify_password_async
from app.core.stepup import StepUpAction, require_recent_auth
from app.core.tenancy import tenant_session
from app.modules.auth.events import record_auth_event
from app.modules.auth.models import AuthEvent, AuthEventType, RevokedReason
from app.modules.identity import sessions_store
from app.modules.identity.errors import LocalReauthRequired
from app.modules.identity.models import ActionPurpose, ActionToken
from app.modules.identity.schemas import PasswordChangeIn, PasswordForgotIn, PasswordResetIn
from app.modules.mail import outbox
from app.modules.mail.templates import MailTemplate
from app.modules.users.models import User, UserKind

log = logging.getLogger(__name__)

FORGOT_IP_LIMIT = 5
FORGOT_IP_WINDOW = 600  # 10 min
FORGOT_EMAIL_LIMIT = 3
FORGOT_EMAIL_WINDOW = 3600  # 1 hour
RESET_TOKEN_TTL = timedelta(minutes=30)


async def process_forgot_password(email: str, ip: str, ua: str) -> None:
    """Background task: looks up the user, creates the reset token, and enqueues mail (RT6)."""
    norm_email = email.strip().lower()
    outbox_id = None
    async with tenant_session(None, None) as session:
        stmt = select(User).where(func.lower(User.email) == norm_email)
        user = (await session.execute(stmt)).scalar_one_or_none()

        eligible = (
            user is not None
            and user.kind == UserKind.HUMAN.value
            and user.is_active
            and user.has_password
        )

        if eligible:
            assert user is not None  # for type checker
            # Consume any existing active reset token for this user
            await session.execute(
                update(ActionToken)
                .where(
                    ActionToken.user_id == user.id,
                    ActionToken.purpose == ActionPurpose.PASSWORD_RESET.value,
                    ActionToken.consumed_at.is_(None),
                    ActionToken.expires_at > func.now(),
                )
                .values(consumed_at=func.now())
            )

            token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode()).hexdigest()

            session.add(
                ActionToken(
                    user_id=user.id,
                    purpose=ActionPurpose.PASSWORD_RESET.value,
                    token_hash=token_hash,
                    email=user.email,
                    expires_at=func.now() + RESET_TOKEN_TTL,
                )
            )
            await session.flush()

            outbox_id = await outbox.enqueue(
                session,
                template=MailTemplate.PASSWORD_RESET,
                to=user.email,
                params={"display_name": user.display_name},
                secret=token,
                user_id=user.id,
            )

            session.add(
                AuthEvent(
                    event=AuthEventType.PASSWORD_RESET_REQUESTED,
                    user_id=user.id,
                    email_attempted=None,
                    ip=ip,
                    user_agent=ua,
                )
            )
        else:
            session.add(
                AuthEvent(
                    event=AuthEventType.PASSWORD_RESET_REQUESTED,
                    user_id=None,
                    email_attempted=None,
                    ip=ip,
                    user_agent=ua,
                )
            )

    if outbox_id is not None:
        await outbox.publish_after_commit([outbox_id])


async def forgot_password(
    body: PasswordForgotIn,
    request: Request,
    background_tasks: BackgroundTasks,
) -> None:
    """POST /auth/password/forgot: rate limited, response sent before DB lookup (RT6)."""
    client_ip_val = client_ip(request)
    ua_val = user_agent(request)
    norm_email = body.email.strip().lower()
    email_hash = hashlib.sha256(norm_email.encode()).hexdigest()

    await rate_limit.hit(f"auth:forgot:ip:{ip_key(request)}", FORGOT_IP_LIMIT, FORGOT_IP_WINDOW)
    await rate_limit.hit(f"auth:forgot:email:{email_hash}", FORGOT_EMAIL_LIMIT, FORGOT_EMAIL_WINDOW)

    background_tasks.add_task(process_forgot_password, norm_email, client_ip_val, ua_val)


async def reset_password(body: PasswordResetIn, request: Request) -> None:
    """POST /auth/password/reset: consumes token, updates password, revokes all sessions."""
    token_hash = hashlib.sha256(body.token.encode()).hexdigest()
    new_hash = await hash_password_async(body.new_password)
    outbox_id = None
    user_id = None

    async with tenant_session(None, None) as session:
        consume_stmt = (
            update(ActionToken)
            .where(
                ActionToken.token_hash == token_hash,
                ActionToken.purpose == ActionPurpose.PASSWORD_RESET.value,
                ActionToken.consumed_at.is_(None),
                ActionToken.expires_at > func.now(),
            )
            .values(consumed_at=func.now())
            .returning(ActionToken.user_id, ActionToken.email)
        )
        res = (await session.execute(consume_stmt)).first()
        if res is None:
            raise NotFound("Invalid or expired reset token", code="token_invalid")
        user_id, token_email = res

        if body.new_password.strip().lower() == token_email.lower():
            raise Conflict("Password must not equal the email address", code="password_equals_email")

        user_stmt = (
            update(User)
            .where(User.id == user_id)
            .values(
                password_hash=new_hash,
                password_changed_at=func.now(),
                email_verified_at=func.coalesce(User.email_verified_at, func.now()),
            )
            .returning(User.display_name)
        )
        user_row = (await session.execute(user_stmt)).first()
        if user_row is None:
            raise NotFound("User not found", code="user_not_found")

        outbox_id = await outbox.enqueue(
            session,
            template=MailTemplate.PASSWORD_CHANGED,
            to=token_email,
            params={"display_name": user_row.display_name},
            user_id=user_id,
        )

        record_auth_event(session, AuthEventType.PASSWORD_RESET, request=request, user_id=user_id)

    assert user_id is not None
    await sessions_store.revoke_all(user_id, reason=RevokedReason.PASSWORD_RESET)
    if outbox_id is not None:
        await outbox.publish_after_commit([outbox_id])


async def change_password(body: PasswordChangeIn, user: CurrentUser, request: Request) -> None:
    """POST /auth/password/change: verifies current password, requires step-up, revokes other sessions."""
    if user.sso_org_id is not None and user.has_password:
        raise LocalReauthRequired()

    outbox_id = None
    new_hash = await hash_password_async(body.new_password)

    async with tenant_session(None, user.id) as session:
        await require_recent_auth(session, user, action=StepUpAction.PASSWORD_CHANGE)

        user_row = (await session.execute(select(User).where(User.id == user.id))).scalar_one_or_none()
        if user_row is None or not user_row.has_password:
            raise Unauthorized("Invalid credentials", code="invalid_credentials")

        valid = await verify_password_async(user_row.password_hash, body.current_password)
        if not valid:
            raise Unauthorized("Invalid credentials", code="invalid_credentials")

        if body.new_password.strip().lower() == user_row.email.lower():
            raise Conflict("Password must not equal the email address", code="password_equals_email")

        user_row.password_hash = new_hash
        user_row.password_changed_at = func.now()

        outbox_id = await outbox.enqueue(
            session,
            template=MailTemplate.PASSWORD_CHANGED,
            to=user_row.email,
            params={"display_name": user_row.display_name},
            user_id=user.id,
        )

        record_auth_event(session, AuthEventType.PASSWORD_CHANGED, request=request, user_id=user.id)

    await sessions_store.revoke_all(user.id, reason=RevokedReason.PASSWORD_RESET, keep=user.session_id)
    if outbox_id is not None:
        await outbox.publish_after_commit([outbox_id])

