import re
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import HTTPConnection

from app.core.client_ip import client_ip, user_agent
from app.modules.audit.models import AuditLog

_SENSITIVE_KEY = re.compile(r"password|token|secret", re.IGNORECASE)


def sanitize(details: dict[str, Any] | None) -> dict[str, Any]:
    if not details:
        return {}
    return {
        key: sanitize(value) if isinstance(value, dict) else value
        for key, value in details.items()
        if not _SENSITIVE_KEY.search(key)
    }


def record(
    session: AsyncSession,
    *,
    action: str,
    org_id: uuid.UUID,
    actor_id: uuid.UUID | None,
    target_type: str | None = None,
    target_id: uuid.UUID | None = None,
    details: dict[str, Any] | None = None,
    request: HTTPConnection | None = None,
) -> AuditLog:
    """Add an audit row to the caller's transaction (atomic with the audited action)."""
    log = AuditLog(
        organization_id=org_id,
        actor_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=sanitize(details),
        ip=client_ip(request) if request else None,
        user_agent=user_agent(request) if request else None,
    )
    session.add(log)
    return log
