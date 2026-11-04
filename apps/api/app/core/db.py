from functools import lru_cache

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import get_settings


@lru_cache
def get_engine() -> AsyncEngine:
    """Process-wide engine for the RLS-bound app role (the API and every worker).

    `hide_parameters`: a failed statement's exception (and so a Celery traceback or an API
    error log) never carries its bound values: IOC values, emails, file names, hashes."""
    return create_async_engine(
        get_settings().database_url,
        pool_size=10,
        max_overflow=10,
        pool_timeout=10,
        pool_pre_ping=True,
        hide_parameters=True,
        connect_args={"timeout": 5},
    )


@lru_cache
def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    # autobegin=False: tenant_session() begins explicitly; a query after commit raises instead
    # of silently running in a new transaction without the RLS context.
    return async_sessionmaker(get_engine(), expire_on_commit=False, autobegin=False)
