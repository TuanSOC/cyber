import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.db import get_sessionmaker

_SET_CONTEXT = text(
    "SELECT set_config('app.user_id', :user_id, true), set_config('app.org_id', :org_id, true)"
)
_SNAPSHOT_READ = text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
_SET_USER = text("SELECT set_config('app.user_id', :user_id, true)")


async def set_app_user(session: AsyncSession, user_id: uuid.UUID) -> None:
    """Set `app.user_id` inside an open tenant session (M11: the service account an API key
    resolved to, `core.rbac.org_session`). Transaction-local, like `tenant_session`'s GUCs."""
    await session.execute(_SET_USER, {"user_id": str(user_id)})


@asynccontextmanager
async def tenant_session(
    org_id: uuid.UUID | None,
    user_id: uuid.UUID | None,
    *,
    sessionmaker: async_sessionmaker[AsyncSession] | None = None,
    snapshot_read: bool = False,
) -> AsyncIterator[AsyncSession]:
    """One transaction with the RLS context set.

    `snapshot_read=True` (M6, RT14) opens the transaction as `REPEATABLE READ READ ONLY`
    before the context is set (`SET TRANSACTION` must precede every query), so a multi-query
    read such as the report snapshot builder sees one instant and can write nothing.

    The GUCs are transaction-local (set_config(..., true) == SET LOCAL), so they reset
    at commit/rollback and never leak to the next user of a pooled connection. A flow
    that needs several transactions opens a new tenant_session for each one.

    Commits on clean exit, rolls back on exception. Callers must leave this block
    (commit) before sending the response; never rely on dependency teardown.
    """
    maker = sessionmaker or get_sessionmaker()
    async with maker() as session, session.begin():
        if snapshot_read:
            await session.execute(_SNAPSHOT_READ)
        await session.execute(
            _SET_CONTEXT,
            {"user_id": str(user_id) if user_id else "", "org_id": str(org_id) if org_id else ""},
        )
        yield session
