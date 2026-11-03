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
    request: HTTPConnection,
    user_id: uuid.UUID | None = None,
    email: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    session.add(
        AuthEvent(
            event=event,
            user_id=user_id,
            email_attempted=email,
            ip=client_ip(request),
            user_agent=user_agent(request),
            details=sanitize(details),
        )
    )
