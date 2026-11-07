"""Session management API service (M11 phase 4)."""

from __future__ import annotations

import uuid

from fastapi import Response
from sqlalchemy import func, select
from starlette.requests import Request

from app.core.cookies import clear_auth_cookies
from app.core.deps import CurrentUser
from app.core.errors import NotFound
from app.core.tenancy import tenant_session
from app.modules.auth.events import record_auth_event
from app.modules.auth.models import AuthEventType, RevokedReason
from app.modules.identity import sessions_store
from app.modules.identity.errors import LocalReauthRequired
from app.modules.identity.models import UserSession
from app.modules.identity.schemas import SessionList, SessionOut
from app.modules.identity.ua import parse_user_agent


async def list_sessions(user: CurrentUser) -> SessionList:
    """GET /auth/sessions: list caller's active, non-revoked sessions."""
    async with tenant_session(None, user.id) as session:
        stmt = (
            select(UserSession)
            .where(
                UserSession.user_id == user.id,
                UserSession.revoked_at.is_(None),
                UserSession.expires_at > func.now(),
            )
            .order_by(UserSession.last_seen_at.desc())
        )
        rows = (await session.execute(stmt)).scalars().all()

        items = [
            SessionOut(
                id=row.id,
                method="sso" if row.method == "sso" else "password",
                amr=list(row.amr or []),
                sso_organization_id=row.sso_org_id,
                created_at=row.created_at,
                last_seen_at=row.last_seen_at,
                expires_at=row.expires_at,
                ip=str(row.ip) if row.ip else None,
                user_agent=parse_user_agent(row.user_agent),
                current=(row.id == user.session_id),
            )
            for row in rows
        ]
        return SessionList(items=items)


async def revoke_session(
    session_id: uuid.UUID,
    user: CurrentUser,
    response: Response,
    request: Request,
) -> None:
    """DELETE /auth/sessions/{session_id}: revoke caller's own session; clear cookies if current."""
    revoked = await sessions_store.revoke(session_id, RevokedReason.USER_REVOKED, user_id=user.id)
    if not revoked:
        raise NotFound("Session not found", code="not_found")

    async with tenant_session(None, user.id) as session:
        record_auth_event(
            session,
            AuthEventType.SESSION_REVOKED,
            request=request,
            user_id=user.id,
            details={"session_id": str(session_id)},
        )

    if session_id == user.session_id:
        clear_auth_cookies(response)


async def revoke_other_sessions(user: CurrentUser, request: Request) -> None:
    """POST /auth/sessions/revoke-others: revoke all active sessions except current."""
    if user.sso_org_id is not None and user.has_password:
        raise LocalReauthRequired()

    revoked_ids = await sessions_store.revoke_all(
        user.id, reason=RevokedReason.USER_REVOKED, keep=user.session_id
    )

    async with tenant_session(None, user.id) as session:
        record_auth_event(
            session,
            AuthEventType.SESSION_REVOKED,
            request=request,
            user_id=user.id,
            details={"revoked_others": True, "count": len(revoked_ids)},
        )

