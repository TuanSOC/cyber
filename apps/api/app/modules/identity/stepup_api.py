"""Step-up authentication route (M11 phase 5).

Provides `POST /auth/step-up` to write `user_sessions.step_up_at = now()` and
re-issue the access token cookie.
- Users with an active/locked TOTP factor must verify with code or recovery code.
- Users without an MFA factor must verify with password.
- SSO sessions get 409 step_up_via_sso.
- API keys are rejected.
"""

from __future__ import annotations

import time

from fastapi import Request, Response
from sqlalchemy import func, select, update

from app.core import rate_limit
from app.core.client_ip import ip_key
from app.core.config import get_settings
from app.core.cookies import set_access_cookie
from app.core.deps import CurrentUser
from app.core.errors import Unauthorized
from app.core.security import verify_password_async
from app.core.tenancy import tenant_session
from app.modules.auth.events import record_auth_event
from app.modules.auth.models import AuthEventType
from app.modules.auth.service import LOGIN_FAILURE_WINDOW_S
from app.modules.auth.sessions import reissue_access
from app.modules.identity import sessions_store, totp
from app.modules.identity.errors import (
    ApiKeyStepUpForbidden,
    BadRequest,
    MfaCodeInvalid,
    StepUpViaSso,
)
from app.modules.identity.mfa import (
    PER_USER_FAILURE_LIMIT,
    PER_USER_FAILURE_WINDOW_S,
    hash_recovery_code,
    normalize_recovery_code,
)
from app.modules.identity.models import (
    MfaFactor,
    MfaStatus,
    MfaType,
    RecoveryCode,
)
from app.modules.identity.schemas import StepUpIn
from app.modules.identity.seal import PROVIDER_TOTP, sealed_from_columns
from app.modules.identity.unseal import open_identity_secret
from app.modules.users import repository as users


async def perform_step_up(
    body: StepUpIn,
    user: CurrentUser,
    request: Request,
    response: Response,
) -> None:
    """Validate step-up credentials, update session step_up_at, and refresh access cookie."""
    if user.kind == "api_key":
        raise ApiKeyStepUpForbidden()

    if user.sso_org_id is not None:
        raise StepUpViaSso()

    settings = get_settings()

    async with tenant_session(None, user.id) as session:
        db_user = await users.get_active(session, user.id)
        if db_user is None or not db_user.is_active:
            raise Unauthorized("User inactive or not found", code="user_inactive")

        stmt = select(MfaFactor).where(
            MfaFactor.user_id == user.id,
            MfaFactor.type == MfaType.TOTP.value,
            MfaFactor.status.in_((MfaStatus.ACTIVE.value, MfaStatus.LOCKED.value)),
        )
        factor = (await session.execute(stmt)).scalar_one_or_none()

        if factor is not None:
            # Factor exists: code or recovery_code required
            if body.password is not None:
                record_auth_event(
                    session,
                    AuthEventType.STEP_UP_FAILURE,
                    request=request,
                    user_id=user.id,
                    email=user.email,
                )
                raise BadRequest("Step-up requires two-factor verification", code="step_up_mfa_required")

            fail_key = f"auth:mfa:fail:{user.id}"
            await rate_limit.hit(fail_key, PER_USER_FAILURE_LIMIT, PER_USER_FAILURE_WINDOW_S)

            if body.code is not None:
                if factor.status == MfaStatus.LOCKED.value:
                    factor.consecutive_failures += 1
                    record_auth_event(
                        session,
                        AuthEventType.STEP_UP_FAILURE,
                        request=request,
                        user_id=user.id,
                        email=user.email,
                    )
                    raise MfaCodeInvalid()

                sealed = sealed_from_columns(factor.kid, factor.key_version, factor.epk, factor.nonce, factor.ct)
                unsealed_secret = open_identity_secret(sealed, user.id, PROVIDER_TOTP).get_secret_value()
                secret_bytes = totp.decode_b32(unsealed_secret)
                matched_step = totp.verify(secret_bytes, body.code, time.time())
                if matched_step is None:
                    factor.consecutive_failures += 1
                    record_auth_event(
                        session,
                        AuthEventType.STEP_UP_FAILURE,
                        request=request,
                        user_id=user.id,
                        email=user.email,
                    )
                    raise MfaCodeInvalid()

                guard_stmt = (
                    update(MfaFactor)
                    .where(
                        MfaFactor.id == factor.id,
                        MfaFactor.status == MfaStatus.ACTIVE.value,
                        MfaFactor.last_used_step < matched_step,
                    )
                    .values(last_used_step=matched_step, consecutive_failures=0)
                    .returning(MfaFactor.id)
                )
                if (await session.execute(guard_stmt)).scalar_one_or_none() is None:
                    factor.consecutive_failures += 1
                    record_auth_event(
                        session,
                        AuthEventType.STEP_UP_FAILURE,
                        request=request,
                        user_id=user.id,
                        email=user.email,
                    )
                    raise MfaCodeInvalid()

            elif body.recovery_code is not None:
                norm = normalize_recovery_code(body.recovery_code)
                code_h = hash_recovery_code(norm)
                code_stmt = (
                    update(RecoveryCode)
                    .where(
                        RecoveryCode.code_hash == code_h,
                        RecoveryCode.user_id == user.id,
                        RecoveryCode.batch_id == factor.recovery_batch_id,
                        RecoveryCode.used_at.is_(None),
                    )
                    .values(used_at=func.now())
                    .returning(RecoveryCode.id)
                )
                if (await session.execute(code_stmt)).scalar_one_or_none() is None:
                    factor.consecutive_failures += 1
                    record_auth_event(
                        session,
                        AuthEventType.STEP_UP_FAILURE,
                        request=request,
                        user_id=user.id,
                        email=user.email,
                    )
                    raise MfaCodeInvalid()
                factor.consecutive_failures = 0
            else:
                raise MfaCodeInvalid()

            await rate_limit.release(fail_key)

        else:
            # No factor enrolled: password required
            if body.password is None:
                record_auth_event(
                    session,
                    AuthEventType.STEP_UP_FAILURE,
                    request=request,
                    user_id=user.id,
                    email=user.email,
                )
                raise BadRequest("Password required for step-up", code="password_required")

            ip = ip_key(request)
            failure_key = f"login:fail:{user.email.lower()}:{ip}"
            await rate_limit.hit(f"login:ip:{ip}", settings.rate_limit_login_per_ip_per_min, 60)
            await rate_limit.hit(failure_key, settings.rate_limit_login_failures_per_15min, LOGIN_FAILURE_WINDOW_S)

            valid = await verify_password_async(db_user.password_hash, body.password)
            if not valid:
                record_auth_event(
                    session,
                    AuthEventType.STEP_UP_FAILURE,
                    request=request,
                    user_id=user.id,
                    email=user.email,
                )
                raise Unauthorized("Invalid password", code="step_up_failed")

            await rate_limit.release(failure_key)

        await sessions_store.mark_step_up(session, user.session_id)
        record_auth_event(
            session,
            AuthEventType.STEP_UP_SUCCESS,
            request=request,
            user_id=user.id,
            email=user.email,
        )

    # Reissue access token and set updated cookie
    new_access = reissue_access(user.id, user.session_id, amr=user.amr, sso_org_id=user.sso_org_id)
    set_access_cookie(response, new_access)
