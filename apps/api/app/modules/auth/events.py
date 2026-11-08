import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import HTTPConnection

from app.core.client_ip import client_ip, user_agent
from app.modules.audit.service import sanitize
from app.modules.auth.models import AuthEvent, AuthEventType


def record_auth_event(
    session: AsyncSession,
    event: AuthEventType,
    *,
    request: HTTPConnection | None = None,
    user_id: uuid.UUID | None = None,
    email: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    ip = client_ip(request) if request is not None else None
    ua = user_agent(request) if request is not None else "cli"
    session.add(
        AuthEvent(
            event=event,
            user_id=user_id,
            email_attempted=email,
            ip=ip,
            user_agent=ua,
            details=sanitize(details),
        )
    )
