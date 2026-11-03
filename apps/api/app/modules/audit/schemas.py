import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, IPvAnyAddress

from app.core.pagination import Page


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    actor_id: uuid.UUID | None
    actor_email: str | None = None
    action: str
    target_type: str | None
    target_id: uuid.UUID | None
    occurred_at: datetime
    ip: IPvAnyAddress | None
    user_agent: str | None
    details: dict[str, Any]


class AuditLogPage(Page[AuditLogOut]):
    pass
