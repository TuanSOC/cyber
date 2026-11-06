"""M11 phase 1: the step-up check (`core.stepup.require_recent_auth`) and the session-store
writes it relies on. The age is compared in SQL against the DB `now()` (RT21); API keys never
pass; the methods follow the account (password, TOTP, recovery code, SSO)."""

import os
import uuid
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from app.core.deps import CurrentUser
from app.core.stepup import StepUpAction, require_recent_auth
from app.core.tenancy import tenant_session
from app.modules.auth.models import RevokedReason
from app.modules.identity import sessions_store
from app.modules.identity.errors import ApiKeyStepUpForbidden, StepUpRequired
from app.modules.identity.models import MfaFactor
from tests.factories import Registered, register
from tests.identity_helpers import get_session_row, session_id_of, set_step_up


def _principal(reg: Registered, **overrides: object) -> CurrentUser:
    user = CurrentUser(
        id=reg.user_id,
        email=reg.email,
        display_name="t",
        jti="test",
        family_id=session_id_of(reg.client),
        token_expires_at=datetime.now(UTC),
    )
    return replace(user, **overrides)  # type: ignore[arg-type]


async def _check(principal: CurrentUser, action: StepUpAction = StepUpAction.MFA_SETUP) -> None:
    async with tenant_session(None, principal.id) as session:
        await require_recent_auth(session, principal, action=action)


async def test_no_recent_step_up_is_refused_with_the_password_method() -> None:
    reg = await register()
    with pytest.raises(StepUpRequired) as refused:
        await _check(_principal(reg), StepUpAction.TLP_DOWNGRADE)
    assert refused.value.extra == {"action": "tlp_downgrade", "methods": ["password"]}


async def test_a_recent_step_up_passes_and_an_old_one_does_not() -> None:
    reg = await register()
    principal = _principal(reg)
    await set_step_up(principal.session_id, seconds_ago=30)
    await _check(principal)
    await set_step_up(principal.session_id, seconds_ago=601)  # STEP_UP_MAX_AGE_S = 600
    with pytest.raises(StepUpRequired):
        await _check(principal)


async def test_mark_step_up_writes_db_time_on_the_live_session_only() -> None:
    reg = await register()
    principal = _principal(reg)
    async with tenant_session(None, reg.user_id) as session:
        await sessions_store.mark_step_up(session, principal.session_id)
    await _check(principal)
    # Another session of the same user is not stepped up.
    other = replace(principal, family_id=uuid.uuid4())
    with pytest.raises(StepUpRequired):
        await _check(other)
    # A revoked session never passes.
    await sessions_store.revoke(
        principal.session_id, RevokedReason.USER_REVOKED, user_id=reg.user_id
    )
    with pytest.raises(StepUpRequired):
        await _check(principal)


async def test_api_keys_never_pass_step_up() -> None:
    reg = await register()
    principal = _principal(reg, kind="api_key", has_password=False)
    await set_step_up(principal.session_id, seconds_ago=1)
    with pytest.raises(ApiKeyStepUpForbidden):
        await _check(principal)


async def test_methods_follow_the_account() -> None:
    reg = await register()
    sso = _principal(reg, sso_org_id=reg.org_id)
    with pytest.raises(StepUpRequired) as refused:
        await _check(sso)
    assert refused.value.extra["methods"] == ["sso"]
    no_password = _principal(reg, has_password=False)
    with pytest.raises(StepUpRequired) as refused:
        await _check(no_password)
    assert refused.value.extra["methods"] == ["sso"]
    async with tenant_session(None, reg.user_id) as session:
        session.add(
            MfaFactor(
                user_id=reg.user_id,
                status="active",
                kid="dev-id-1",
                key_version=1,
                epk=os.urandom(32),
                nonce=os.urandom(12),
                ct=os.urandom(48),
                confirmed_at=datetime.now(UTC),
            )
        )
    with pytest.raises(StepUpRequired) as refused:
        await _check(_principal(reg))
    assert refused.value.extra["methods"] == ["totp", "recovery_code"]


async def test_add_amr_records_the_mfa_time_once() -> None:
    reg = await register()
    sid = session_id_of(reg.client)
    async with tenant_session(None, reg.user_id) as session:
        assert await sessions_store.add_amr(session, sid, "otp") == ["pwd", "otp"]
        assert await sessions_store.add_amr(session, sid, "otp") == ["pwd", "otp"]
    row = await get_session_row(sid)
    assert row is not None and row.mfa_at is not None and row.amr == ["pwd", "otp"]
    with pytest.raises(ValueError):
        async with tenant_session(None, reg.user_id) as session:
            await sessions_store.add_amr(session, sid, "magic")
