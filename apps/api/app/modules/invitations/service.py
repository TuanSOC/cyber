"""Invitations (M11; phase 1 stubs, phase 3 implements them).

`register_with_invitation` is called by `auth.service.register` when `RegisterIn.invitation_
token` is set (FROZEN signature): it finds the org through `invitation_index` (system
session), then in ONE `tenant_session(org, new user)` (the vetted entry of
`tests/unit/test_tenant_session_guard.py`) creates the user (`email_verified_at = now()`),
consumes the invitation atomically (`UPDATE … WHERE token_hash AND pending AND not expired
RETURNING`), inserts the membership, writes `invitation.accepted` and `member.added`
(`via: invitation`) audit rows and the `register` / `invitation_accepted` auth events and
starts the session. No new org and no owned-org count. The emails must match, else `409
invitation_email_mismatch` and nothing is created; an unknown, used, revoked or expired token
is `404 invitation_invalid`.
"""

import uuid

from starlette.requests import HTTPConnection

from app.core.cookies import IssuedTokens
from app.core.stubs import not_implemented
from app.modules.auth.schemas import RegisterIn


async def register_with_invitation(
    data: RegisterIn, password_hash: str, request: HTTPConnection
) -> tuple[uuid.UUID, IssuedTokens]:
    """Returns (the new user's id, its session tokens). 501 until phase 3."""
    raise not_implemented()
