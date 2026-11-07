"""Sessions and the personal security log (M11 phase 4).

Revocations go through `identity.sessions_store.revoke` / `revoke_all` (reason
`user_revoked`) and write `session_revoked`; `revoke-others` is refused from an SSO session of
a password user (RT2). `GET /auth/events` lists the caller's own auth events (limit <= 100).
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Query, Request, Response, status

from app.core.deps import CurrentUserDep
from app.modules.identity import events_api, sessions_api
from app.modules.identity.schemas import AuthEventList, SessionList

router = APIRouter(prefix="/auth", tags=["identity"])


@router.get("/sessions", response_model=SessionList)
async def list_sessions(user: CurrentUserDep) -> SessionList:
    return await sessions_api.list_sessions(user)


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_session(
    session_id: uuid.UUID,
    user: CurrentUserDep,
    response: Response,
    request: Request,
) -> None:
    await sessions_api.revoke_session(session_id, user, response, request)


@router.post("/sessions/revoke-others", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_other_sessions(user: CurrentUserDep, request: Request) -> None:
    await sessions_api.revoke_other_sessions(user, request)


@router.get("/events", response_model=AuthEventList)
async def list_auth_events(
    user: CurrentUserDep, limit: Annotated[int, Query(ge=1, le=100)] = 50
) -> AuthEventList:
    return await events_api.list_auth_events(user, limit)
