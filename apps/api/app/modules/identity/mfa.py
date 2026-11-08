"""MFA enrollment, status, recovery codes, disable, and verify (M11 phase 5).

Handles:
- Base32 TOTP secret generation, sealing at rest, and pending factor creation.
- Confirmation: unsealing, step verification, 10 recovery codes generation, session AMR update,
  revocation of other sessions, event logging, and email notification.
- Status querying: factor state, remaining recovery codes, org MFA policy checks.
- Recovery code regeneration with step-up verification.
- Factor disabling: second factor step-up verification, org policy enforcement, revocation.
- Login challenge verification: rate limiting, replay guard, lockouts, and session issuance.
"""

from __future__ import annotations

import hashlib
import secrets
import time
import uuid
from datetime import timedelta
from typing import Any

from fastapi import Request, Response
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import rate_limit
from app.core.cookies import (
    MFA_COOKIE,
    clear_mfa_cookie,
    set_access_cookie,
    set_auth_cookies,
)
from app.core.deps import CurrentUser
from app.core.errors import Conflict, NotFound, Unauthorized
from app.core.stepup import StepUpAction, require_recent_auth
from app.core.tenancy import tenant_session
from app.modules.auth import service as auth_service
from app.modules.auth import sessions
from app.modules.auth.events import record_auth_event
from app.modules.auth.models import AuthEventType, RevokedReason
from app.modules.auth.schemas import MeOut
from app.modules.auth.sessions import reissue_access
from app.modules.identity import sessions_store, totp
from app.modules.identity.challenge import (
    MAX_CHALLENGE_ATTEMPTS,
    delete_challenge,
    get_challenge,
    increment_attempts,
)
from app.modules.identity.errors import (
    EmailVerificationRequired,
    LocalReauthRequired,
    MfaChallengeInvalid,
    MfaCodeInvalid,
    MfaRequiredByOrg,
)
from app.modules.identity.models import (
    MfaFactor,
    MfaStatus,
    MfaType,
    OrgSecurityPolicy,
    RecoveryCode,
    SessionMethod,
)
from app.modules.identity.schemas import (
    MfaStatusOut,
    MfaVerifyIn,
    RecoveryCodesOut,
    TotpConfirmIn,
    TotpDisableIn,
    TotpSetupOut,
)
from app.modules.identity.seal import (
    PROVIDER_TOTP,
    seal_totp_secret,
    sealed_from_columns,
)
from app.modules.identity.unseal import open_identity_secret
from app.modules.mail import outbox
from app.modules.mail.templates import MailTemplate
from app.modules.organizations.models import OrganizationMember
from app.modules.users import repository as users

CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
PENDING_FACTOR_TTL = timedelta(minutes=15)
PER_USER_FAILURE_LIMIT = 10
PER_USER_FAILURE_WINDOW_S = 15 * 60
CONSECUTIVE_FAILURES_LOCK = 100


def normalize_recovery_code(code: str) -> str:
    """Normalize recovery code: strip whitespace/hyphens, uppercase, I/L -> 1, O -> 0."""
    clean = code.strip().upper().replace(" ", "").replace("-", "")
    return clean.replace("I", "1").replace("L", "1").replace("O", "0")


def hash_recovery_code(normalized_code: str) -> str:
    """Compute SHA-256 hex digest of normalized recovery code."""
    return hashlib.sha256(normalized_code.encode("ascii")).hexdigest()


def generate_recovery_codes() -> tuple[list[str], list[str]]:
    """Generate 10 recovery codes with 80-bit entropy in Crockford Base32.

    Returns (formatted_display_codes, sha256_hashes).
    """
    display_codes: list[str] = []
    hashes: list[str] = []
    for _ in range(10):
        raw = secrets.token_bytes(10)
        num = int.from_bytes(raw, "big")
        chars: list[str] = []
        for _ in range(16):
            chars.append(CROCKFORD_ALPHABET[num & 0x1F])
            num >>= 5
        raw_str = "".join(reversed(chars))
        formatted = f"{raw_str[0:4]}-{raw_str[4:8]}-{raw_str[8:12]}-{raw_str[12:16]}"
        display_codes.append(formatted)
        hashes.append(hash_recovery_code(normalize_recovery_code(formatted)))
    return display_codes, hashes


async def _assert_local_reauth(user: CurrentUser) -> None:
    """Refuse SSO sessions of users with local passwords (RT2)."""
    if user.sso_org_id is not None and user.has_password:
        raise LocalReauthRequired()


async def setup_totp(user: CurrentUser, session: AsyncSession) -> TotpSetupOut:
    """Generate a new TOTP secret, seal it, and store as a pending factor."""
    await _assert_local_reauth(user)

    db_user = await users.get_active(session, user.id)
    if db_user is None or db_user.email_verified_at is None:
        raise EmailVerificationRequired()

    await require_recent_auth(session, user, action=StepUpAction.MFA_SETUP)

    # Check existing factor
    stmt = select(MfaFactor).where(
        MfaFactor.user_id == user.id,
        MfaFactor.type == MfaType.TOTP.value,
        MfaFactor.status.in_((MfaStatus.ACTIVE.value, MfaStatus.LOCKED.value, MfaStatus.PENDING.value)),
    )
    existing = (await session.execute(stmt)).scalar_one_or_none()
    if existing is not None and existing.status == MfaStatus.ACTIVE.value:
        raise Conflict("Two-factor authentication is already active", code="mfa_already_active")

    secret_bytes = totp.new_secret()
    secret_b32 = totp.b32(secret_bytes)
    sealed = seal_totp_secret(secret_b32, user.id)

    if existing is not None:
        # Replace pending or locked factor
        existing.kid = sealed.kid
        existing.key_version = sealed.key_version
        existing.epk = sealed.epk
        existing.nonce = sealed.nonce
        existing.ct = sealed.ct
        existing.status = MfaStatus.PENDING.value
        existing.created_at = func.now()
        existing.last_used_step = 0
        existing.consecutive_failures = 0
    else:
        factor = MfaFactor(
            user_id=user.id,
            type=MfaType.TOTP.value,
            status=MfaStatus.PENDING.value,
            kid=sealed.kid,
            key_version=sealed.key_version,
            epk=sealed.epk,
            nonce=sealed.nonce,
            ct=sealed.ct,
            last_used_step=0,
            consecutive_failures=0,
        )
        session.add(factor)

    uri = totp.otpauth_uri(secret_bytes, account=db_user.email, issuer="CyberLab")
    return TotpSetupOut(otpauth_uri=uri, secret=secret_b32)


async def confirm_totp(
    body: TotpConfirmIn,
    user: CurrentUser,
    session: AsyncSession,
    request: Request,
    response: Response,
) -> RecoveryCodesOut:
    """Verify code against pending factor, activate factor, and issue recovery codes."""
    await _assert_local_reauth(user)

    stmt = select(MfaFactor).where(
        MfaFactor.user_id == user.id,
        MfaFactor.type == MfaType.TOTP.value,
        MfaFactor.status == MfaStatus.PENDING.value,
        MfaFactor.created_at > func.now() - PENDING_FACTOR_TTL,
    )
    factor = (await session.execute(stmt)).scalar_one_or_none()
    if factor is None:
        raise NotFound("No pending MFA setup found", code="mfa_factor_not_found")

    sealed = sealed_from_columns(factor.kid, factor.key_version, factor.epk, factor.nonce, factor.ct)
    unsealed_secret = open_identity_secret(sealed, user.id, PROVIDER_TOTP).get_secret_value()
    secret_bytes = totp.decode_b32(unsealed_secret)

    matched_step = totp.verify(secret_bytes, body.code, time.time())
    if matched_step is None:
        raise MfaCodeInvalid()

    batch_id = uuid.uuid4()
    display_codes, hashes = generate_recovery_codes()
    for code_h in hashes:
        session.add(RecoveryCode(user_id=user.id, batch_id=batch_id, code_hash=code_h))

    factor.status = MfaStatus.ACTIVE.value
    factor.confirmed_at = func.now()
    factor.last_used_step = matched_step
    factor.consecutive_failures = 0
    factor.recovery_batch_id = batch_id

    # Add OTP to current session AMR and refresh access cookie
    new_amr = await sessions_store.add_amr(session, user.session_id, "otp")
    access_token = reissue_access(user.id, user.session_id, amr=new_amr, sso_org_id=user.sso_org_id)
    set_access_cookie(response, access_token)

    # Revoke all other sessions
    await sessions_store.revoke_all(user.id, reason=RevokedReason.MFA_CHANGE, keep=user.session_id)

    record_auth_event(session, AuthEventType.MFA_ENABLED, request=request, user_id=user.id, email=user.email)
    await outbox.enqueue(
        session,
        template=MailTemplate.MFA_ENABLED,
        to=user.email,
        params={"display_name": user.display_name},
        user_id=user.id,
    )

    return RecoveryCodesOut(codes=display_codes)


async def get_mfa_status(user: CurrentUser, session: AsyncSession) -> MfaStatusOut:
    """Get caller's MFA configuration status, recovery code counts, and org policies."""
    db_user = await users.get_active(session, user.id)
    email_verified = db_user.email_verified_at is not None if db_user else False

    stmt = select(MfaFactor).where(
        MfaFactor.user_id == user.id,
        MfaFactor.type == MfaType.TOTP.value,
        MfaFactor.status != MfaStatus.DISABLED.value,
    )
    factor = (await session.execute(stmt)).scalar_one_or_none()

    totp_status: Any = factor.status if factor is not None else "none"
    confirmed_at = factor.confirmed_at if factor is not None else None

    remaining_codes = 0
    if factor is not None and factor.recovery_batch_id is not None:
        count_stmt = select(func.count(RecoveryCode.id)).where(
            RecoveryCode.batch_id == factor.recovery_batch_id,
            RecoveryCode.used_at.is_(None),
        )
        remaining_codes = (await session.execute(count_stmt)).scalar_one() or 0

    # Read required orgs
    org_stmt = (
        select(OrgSecurityPolicy.organization_id)
        .join(OrganizationMember, OrganizationMember.organization_id == OrgSecurityPolicy.organization_id)
        .where(
            OrganizationMember.user_id == user.id,
            OrgSecurityPolicy.require_mfa.is_(True),
        )
    )
    required_orgs = list((await session.execute(org_stmt)).scalars())

    return MfaStatusOut(
        totp=totp_status,
        confirmed_at=confirmed_at,
        recovery_codes_remaining=remaining_codes,
        email_verified=email_verified,
        required_by_orgs=required_orgs,
    )


async def regenerate_recovery_codes(
    user: CurrentUser,
    session: AsyncSession,
    request: Request,
) -> RecoveryCodesOut:
    """Generate a fresh batch of 10 recovery codes, invalidating prior batches."""
    await _assert_local_reauth(user)
    await require_recent_auth(session, user, action=StepUpAction.RECOVERY_CODES_REGENERATE)

    stmt = select(MfaFactor).where(
        MfaFactor.user_id == user.id,
        MfaFactor.type == MfaType.TOTP.value,
        MfaFactor.status == MfaStatus.ACTIVE.value,
    )
    factor = (await session.execute(stmt)).scalar_one_or_none()
    if factor is None:
        raise NotFound("No active two-factor authentication factor", code="mfa_factor_not_found")

    batch_id = uuid.uuid4()
    display_codes, hashes = generate_recovery_codes()
    for code_h in hashes:
        session.add(RecoveryCode(user_id=user.id, batch_id=batch_id, code_hash=code_h))

    factor.recovery_batch_id = batch_id

    record_auth_event(
        session,
        AuthEventType.RECOVERY_CODES_REGENERATED,
        request=request,
        user_id=user.id,
        email=user.email,
    )

    return RecoveryCodesOut(codes=display_codes)


async def disable_totp(
    body: TotpDisableIn,
    user: CurrentUser,
    session: AsyncSession,
    request: Request,
) -> None:
    """Disable TOTP factor after verifying second factor and checking org policies."""
    await _assert_local_reauth(user)
    await require_recent_auth(session, user, action=StepUpAction.MFA_DISABLE)

    stmt = select(MfaFactor).where(
        MfaFactor.user_id == user.id,
        MfaFactor.type == MfaType.TOTP.value,
        MfaFactor.status.in_((MfaStatus.ACTIVE.value, MfaStatus.LOCKED.value)),
    )
    factor = (await session.execute(stmt)).scalar_one_or_none()
    if factor is None:
        raise NotFound("No active two-factor authentication factor", code="mfa_factor_not_found")

    # Verify second factor provided in body (TOTP code or recovery code)
    if body.code is not None:
        sealed = sealed_from_columns(factor.kid, factor.key_version, factor.epk, factor.nonce, factor.ct)
        unsealed_secret = open_identity_secret(sealed, user.id, PROVIDER_TOTP).get_secret_value()
        secret_bytes = totp.decode_b32(unsealed_secret)
        matched_step = totp.verify(secret_bytes, body.code, time.time())
        if matched_step is None:
            raise MfaCodeInvalid()
        # Atomic replay guard update
        guard_stmt = (
            update(MfaFactor)
            .where(MfaFactor.id == factor.id, MfaFactor.last_used_step < matched_step)
            .values(last_used_step=matched_step)
            .returning(MfaFactor.id)
        )
        if (await session.execute(guard_stmt)).scalar_one_or_none() is None:
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
            raise MfaCodeInvalid()
    else:
        raise MfaCodeInvalid()

    # Check org policy enforcement (RT13)
    org_stmt = (
        select(OrgSecurityPolicy.organization_id)
        .join(OrganizationMember, OrganizationMember.organization_id == OrgSecurityPolicy.organization_id)
        .where(
            OrganizationMember.user_id == user.id,
            OrgSecurityPolicy.require_mfa.is_(True),
        )
    )
    if (await session.execute(org_stmt)).first() is not None:
        raise MfaRequiredByOrg()

    factor.status = MfaStatus.DISABLED.value
    factor.disabled_at = func.now()
    factor.recovery_batch_id = None

    await sessions_store.revoke_all(user.id, reason=RevokedReason.MFA_CHANGE, keep=user.session_id)

    record_auth_event(session, AuthEventType.MFA_DISABLED, request=request, user_id=user.id, email=user.email)
    await outbox.enqueue(
        session,
        template=MailTemplate.MFA_DISABLED,
        to=user.email,
        params={"display_name": user.display_name},
        user_id=user.id,
    )


async def verify_login_mfa(
    body: MfaVerifyIn,
    request: Request,
    response: Response,
) -> MeOut:
    """Verify login challenge with TOTP code or recovery code and issue session."""
    challenge_id = request.cookies.get(MFA_COOKIE)
    if not challenge_id:
        raise MfaChallengeInvalid()

    challenge_data = await get_challenge(challenge_id)
    if challenge_data is None:
        raise MfaChallengeInvalid()

    attempts = await increment_attempts(challenge_id)
    if attempts > MAX_CHALLENGE_ATTEMPTS:
        await delete_challenge(challenge_id)
        raise MfaChallengeInvalid()

    user_id = uuid.UUID(challenge_data["user_id"])
    fail_key = f"auth:mfa:fail:{user_id}"
    await rate_limit.hit(fail_key, PER_USER_FAILURE_LIMIT, PER_USER_FAILURE_WINDOW_S)

    async with tenant_session(None, user_id) as session:
        db_user = await users.get_active(session, user_id)
        if db_user is None or not db_user.is_active:
            await delete_challenge(challenge_id)
            raise MfaChallengeInvalid()

        current_pwd_changed = db_user.password_changed_at.isoformat() if db_user.password_changed_at else None
        if current_pwd_changed != challenge_data.get("password_changed_at"):
            await delete_challenge(challenge_id)
            raise MfaChallengeInvalid()

        stmt = select(MfaFactor).where(
            MfaFactor.user_id == user_id,
            MfaFactor.type == MfaType.TOTP.value,
            MfaFactor.status.in_((MfaStatus.ACTIVE.value, MfaStatus.LOCKED.value)),
        )
        factor = (await session.execute(stmt)).scalar_one_or_none()
        if factor is None:
            await delete_challenge(challenge_id)
            raise MfaChallengeInvalid()

        if body.code is not None:
            if factor.status == MfaStatus.LOCKED.value:
                factor.consecutive_failures += 1
                record_auth_event(session, AuthEventType.MFA_FAILURE, request=request, user_id=user_id, email=db_user.email)
                await session.commit()
                raise MfaCodeInvalid()

            sealed = sealed_from_columns(factor.kid, factor.key_version, factor.epk, factor.nonce, factor.ct)
            unsealed_secret = open_identity_secret(sealed, user_id, PROVIDER_TOTP).get_secret_value()
            secret_bytes = totp.decode_b32(unsealed_secret)
            matched_step = totp.verify(secret_bytes, body.code, time.time())
            if matched_step is None:
                factor.consecutive_failures += 1
                if factor.consecutive_failures >= CONSECUTIVE_FAILURES_LOCK:
                    factor.status = MfaStatus.LOCKED.value
                    record_auth_event(session, AuthEventType.MFA_LOCKED, request=request, user_id=user_id, email=db_user.email)
                    await outbox.enqueue(
                        session,
                        template=MailTemplate.MFA_LOCKED,
                        to=db_user.email,
                        params={"display_name": db_user.display_name},
                        user_id=user_id,
                    )
                else:
                    record_auth_event(session, AuthEventType.MFA_FAILURE, request=request, user_id=user_id, email=db_user.email)
                await session.commit()
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
                record_auth_event(session, AuthEventType.MFA_FAILURE, request=request, user_id=user_id, email=db_user.email)
                await session.commit()
                raise MfaCodeInvalid()

            amr = ["pwd", "otp"]
            event_type = AuthEventType.MFA_SUCCESS

        elif body.recovery_code is not None:
            norm = normalize_recovery_code(body.recovery_code)
            code_h = hash_recovery_code(norm)
            code_stmt = (
                update(RecoveryCode)
                .where(
                    RecoveryCode.code_hash == code_h,
                    RecoveryCode.user_id == user_id,
                    RecoveryCode.batch_id == factor.recovery_batch_id,
                    RecoveryCode.used_at.is_(None),
                )
                .values(used_at=func.now())
                .returning(RecoveryCode.id)
            )
            if (await session.execute(code_stmt)).scalar_one_or_none() is None:
                factor.consecutive_failures += 1
                if factor.consecutive_failures >= CONSECUTIVE_FAILURES_LOCK:
                    factor.status = MfaStatus.LOCKED.value
                    record_auth_event(session, AuthEventType.MFA_LOCKED, request=request, user_id=user_id, email=db_user.email)
                    await outbox.enqueue(
                        session,
                        template=MailTemplate.MFA_LOCKED,
                        to=db_user.email,
                        params={"display_name": db_user.display_name},
                        user_id=user_id,
                    )
                else:
                    record_auth_event(session, AuthEventType.MFA_FAILURE, request=request, user_id=user_id, email=db_user.email)
                await session.commit()
                raise MfaCodeInvalid()

            factor.consecutive_failures = 0
            rem_stmt = select(func.count(RecoveryCode.id)).where(
                RecoveryCode.batch_id == factor.recovery_batch_id,
                RecoveryCode.used_at.is_(None),
            )
            remaining = (await session.execute(rem_stmt)).scalar_one() or 0
            await outbox.enqueue(
                session,
                template=MailTemplate.RECOVERY_CODE_USED,
                to=db_user.email,
                params={"display_name": db_user.display_name, "remaining": remaining},
                user_id=user_id,
            )
            amr = ["pwd", "recovery"]
            event_type = AuthEventType.RECOVERY_CODE_USED
        else:
            raise MfaCodeInvalid()

        await rate_limit.release(fail_key)
        issued = await sessions.start_session(
            session,
            user_id,
            request,
            method=SessionMethod.PASSWORD,
            amr=amr,
        )
        record_auth_event(
            session,
            event_type,
            request=request,
            user_id=user_id,
            email=db_user.email,
        )

    await delete_challenge(challenge_id)
    clear_mfa_cookie(response)
    set_auth_cookies(response, issued)
    return await auth_service.me(user_id)
