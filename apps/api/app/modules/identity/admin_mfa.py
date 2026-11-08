"""`pnpm identity:admin reset-mfa --email <e> [--yes]` (M11 phase 5).

Disables the factor and recovery codes, revokes every session
(`sessions_store.revoke_all(reason=RevokedReason.OPERATOR)`), records
`mfa_reset_by_operator` auth event and mails the user.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

from sqlalchemy import func, select

from app.core.tenancy import tenant_session
from app.modules.auth.events import record_auth_event
from app.modules.auth.models import AuthEventType, RevokedReason
from app.modules.identity import sessions_store
from app.modules.identity.models import MfaFactor, MfaStatus, MfaType
from app.modules.mail import outbox
from app.modules.mail.templates import MailTemplate
from app.modules.users import repository as users_repo


async def reset_mfa(email: str, confirmed: bool) -> tuple[int, str]:
    email_clean = email.strip().lower()

    async with tenant_session(None, None) as session:
        user = await users_repo.get_by_email(session, email_clean)
        if user is None:
            return 1, f"Error: user '{email_clean}' not found"

        if not user.is_active or user.kind != "human":
            return 1, f"Error: user '{email_clean}' is not an active human account"

        stmt = select(MfaFactor).where(
            MfaFactor.user_id == user.id,
            MfaFactor.type == MfaType.TOTP.value,
            MfaFactor.status.in_((MfaStatus.ACTIVE.value, MfaStatus.LOCKED.value, MfaStatus.PENDING.value)),
        )
        factor = (await session.execute(stmt)).scalar_one_or_none()
        if factor is None:
            return 1, f"Error: user '{email_clean}' has no MFA factor enrolled"

        if not confirmed:
            return 2, f"Will disable MFA and revoke all sessions for {email_clean}. Pass --yes to confirm."

        factor.status = MfaStatus.DISABLED.value
        factor.disabled_at = func.now()
        factor.recovery_batch_id = None

        await sessions_store.revoke_all(user.id, reason=RevokedReason.OPERATOR)

        operator_name = os.environ.get("USER") or os.environ.get("USERNAME") or "operator"
        record_auth_event(
            session,
            AuthEventType.MFA_RESET_BY_OPERATOR,
            user_id=user.id,
            email=email_clean,
            details={"operator": operator_name},
        )

        await outbox.enqueue(
            session,
            template=MailTemplate.MFA_RESET_BY_OPERATOR,
            to=user.email,
            params={"display_name": user.display_name},
            user_id=user.id,
        )

    return 0, f"MFA reset successfully for {email_clean}. All sessions revoked and notification enqueued."


async def run_async(args: argparse.Namespace) -> int:
    email = getattr(args, "email", None)
    confirmed = getattr(args, "yes", False)

    if not email:
        print("Usage: identity:admin reset-mfa --email <email> [--yes]", file=sys.stderr)
        return 2

    code, message = await reset_mfa(email, confirmed)
    if code != 0:
        print(message, file=sys.stderr)
        return code

    print(message)
    return 0


def run(args: argparse.Namespace) -> int:
    return asyncio.run(run_async(args))
