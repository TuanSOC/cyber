import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.db import get_sessionmaker

_SET_CONTEXT = text(
    "SELECT set_config('app.user_id', :user_id, true), set_config('app.org_id', :org_id, true)"
)


@asynccontextmanager
async def tenant_session(
    org_id: uuid.UUID | None,
    user_id: uuid.UUID | None,
    *,
    sessionmaker: async_sessionmaker[AsyncSession] | None = None,
) -> AsyncIterator[AsyncSession]:
    """One transaction with the RLS context set.

    The GUCs are transaction-local (set_config(..., true) == SET LOCAL), so they reset
    at commit/rollback and never leak to the next user of a pooled connection. A flow
    that needs several transactions opens a new tenant_session for each one.

    Commits on clean exit, rolls back on exception. Callers must leave this block
    (commit) before sending the response; never rely on dependency teardown.
    """
    maker = sessionmaker or get_sessionmaker()
    async with maker() as session, session.begin():
        await session.execute(
            _SET_CONTEXT,
            {"user_id": str(user_id) if user_id else "", "org_id": str(org_id) if org_id else ""},
        )
        yield session
