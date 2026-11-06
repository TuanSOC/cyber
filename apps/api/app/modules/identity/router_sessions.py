"""Sessions and the personal security log (M11 phase 4; phase 1 stubs answering 501).

Revocations go through `identity.sessions_store.revoke` / `revoke_all` (reason
`user_revoked`) and write `session_revoked`; `revoke-others` is refused from an SSO session of
a password user (RT2). `GET /auth/events` lists the caller's own auth events (limit <= 100).
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Query, status

from app.core.deps import CurrentUserDep
from app.core.stubs import not_implemented
from app.modules.identity.schemas import AuthEventList, SessionList

router = APIRouter(prefix="/auth", tags=["identity"])


@router.get("/sessions", response_model=SessionList)
async def list_sessions(user: CurrentUserDep) -> SessionList:
    raise not_implemented()


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_session(session_id: uuid.UUID, user: CurrentUserDep) -> None:
    raise not_implemented()


@router.post("/sessions/revoke-others", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_other_sessions(user: CurrentUserDep) -> None:
    raise not_implemented()


@router.get("/events", response_model=AuthEventList)
async def list_auth_events(
    user: CurrentUserDep, limit: Annotated[int, Query(ge=1, le=100)] = 50
) -> AuthEventList:
    raise not_implemented()
