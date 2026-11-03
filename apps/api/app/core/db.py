from functools import lru_cache

from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from app.core.config import get_settings


@lru_cache
def get_engine() -> AsyncEngine:
    """Process-wide engine for the RLS-bound app role (tenant sessions are added in phase 2)."""
    return create_async_engine(
        get_settings().database_url,
        pool_size=10,
        max_overflow=10,
        pool_timeout=10,
        pool_pre_ping=True,
        connect_args={"timeout": 5},
    )
