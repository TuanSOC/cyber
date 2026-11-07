"""Email verification logic (M11 phase 3).

Enforces link scanner resistance (RT8):
- `verify-request` mails a 24-hour token (3 / hour per user).
- `verify` requires a live session of the token's own user (`user_action_tokens.user_id == current_user.id`),
  ensuring that automated link previewers or forwarded links cannot silently verify an account.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import logging
import secrets

from sqlalchemy import func, update
from starlette.requests import HTTPConnection

from app.core import rate_limit
from app.core.deps import CurrentUser
from app.core.errors import NotFound
from app.core.tenancy import tenant_session
from app.modules.auth.events import record_auth_event
from app.modules.auth.models import AuthEventType
from app.modules.identity.models import ActionToken
from app.modules.mail import outbox
from app.modules.mail.templates import MailTemplate
from app.modules.users.models import User

log = logging.getLogger(__name__)

PURPOSE_EMAIL_VERIFY = "email_verify"
VERIFY_EXPIRY_HOURS = 24


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def request_verification(user: CurrentUser, request: HTTPConnection) -> None:
    # 1. Rate limit: 3 requests per hour per user
    await rate_limit.hit(f"verify_email:user:{user.id}", 3, 3600)

    token = secrets.token_urlsafe(32)
    token_hash = _hash_token(token)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=VERIFY_EXPIRY_HOURS)

    async with tenant_session(None, user.id) as session:
        action_token = ActionToken(
            user_id=user.id,
            purpose=PURPOSE_EMAIL_VERIFY,
            token_hash=token_hash,
            email=user.email,
            expires_at=expires_at,
        )
        session.add(action_token)

        outbox_id = await outbox.enqueue(
            session,
            template=MailTemplate.EMAIL_VERIFY,
            to=user.email,
            params={"display_name": user.display_name},
            secret=token,
            user_id=user.id,
        )

    await outbox.publish_after_commit(outbox_id)


async def verify_email(user: CurrentUser, token: str, request: HTTPConnection) -> None:
    token_hash = _hash_token(token)

    async with tenant_session(None, user.id) as session:
        # Atomic consume: must match token_hash, user_id, purpose, unconsumed, unexpired (RT8)
        stmt = (
            update(ActionToken)
            .where(
                ActionToken.token_hash == token_hash,
                ActionToken.user_id == user.id,
                ActionToken.purpose == PURPOSE_EMAIL_VERIFY,
                ActionToken.consumed_at.is_(None),
                ActionToken.expires_at > func.now(),
            )
            .values(consumed_at=func.now())
            .returning(ActionToken)
        )
        res = await session.execute(stmt)
        token_row = res.scalar_one_or_none()
        if token_row is None:
            raise NotFound("Invalid or expired verification token", code="token_invalid")

        # Update user email_verified_at if token email still matches current email
        if token_row.email.lower() == user.email.lower():
            await session.execute(
                update(User)
                .where(User.id == user.id)
                .values(email_verified_at=func.coalesce(User.email_verified_at, func.now()))
            )

        record_auth_event(
            session,
            AuthEventType.EMAIL_VERIFIED,
            request=request,
            user_id=user.id,
        )

