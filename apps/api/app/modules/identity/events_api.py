"""Personal security log API service (M11 phase 4)."""

from __future__ import annotations

from sqlalchemy import select

from app.core.deps import CurrentUser
from app.core.tenancy import tenant_session
from app.modules.auth.models import AuthEvent
from app.modules.identity.schemas import AuthEventList, AuthEventOut
from app.modules.identity.ua import parse_user_agent


async def list_auth_events(user: CurrentUser, limit: int = 50) -> AuthEventList:
    """GET /auth/events: list the caller's personal security events, newest first."""
    clamped_limit = max(1, min(limit, 100))

    async with tenant_session(None, user.id) as session:
        stmt = (
            select(AuthEvent)
            .where(AuthEvent.user_id == user.id)
            .order_by(AuthEvent.occurred_at.desc())
            .limit(clamped_limit)
        )
        rows = (await session.execute(stmt)).scalars().all()

        items = [
            AuthEventOut(
                id=row.id,
                event=row.event.value if hasattr(row.event, "value") else str(row.event),
                occurred_at=row.occurred_at,
                ip=str(row.ip) if row.ip else None,
                user_agent=parse_user_agent(row.user_agent),
            )
            for row in rows
        ]
        return AuthEventList(items=items)

