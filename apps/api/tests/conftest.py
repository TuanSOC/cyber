import os
import subprocess
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.clients import get_redis
from app.core.config import RETENTION_SYSTEM_USER_EMAIL, RETENTION_SYSTEM_USER_ID, get_settings
from app.core.db import get_engine
from app.models import Base
from tests.analysis_helpers import purge_test_queues
from tests.storage_helpers import forget_owned_orgs, purge_owned

API_ROOT = Path(__file__).resolve().parents[1]


def assert_test_database(url: str) -> None:
    """Refuse to touch anything but a *_test database (cleanup truncates every table)."""
    name = make_url(url).database or ""
    if not name.endswith("_test"):
        raise RuntimeError(f"refusing to run tests against database {name!r} (must end with _test)")


def assert_test_redis(url: str) -> None:
    """Refuse Redis db 0 (the dev stack's db): cleanup runs FLUSHDB."""
    parsed = urlparse(url)
    db = parse_qs(parsed.query).get("db", [parsed.path.lstrip("/") or "0"])[0]
    if db == "0":
        raise RuntimeError("refusing to flush Redis db 0 in tests (use a non-zero db)")


def _owner_url() -> str:
    return os.environ["TEST_MIGRATION_DATABASE_URL"]


@pytest.fixture(scope="session", autouse=True)
def _migrated_test_database() -> None:
    settings = get_settings()
    if settings.env != "test":
        raise RuntimeError("tests must run with ENV=test (use the api-test compose service)")
    assert_test_database(settings.database_url)
    assert_test_database(_owner_url())
    assert_test_redis(settings.need("redis_url"))
    subprocess.run(
        ["alembic", "upgrade", "head"],
        check=True,
        cwd=API_ROOT,
        env={**os.environ, "MIGRATION_DATABASE_URL": _owner_url()},
    )


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def owner_engine() -> AsyncIterator[AsyncEngine]:
    """Table-owner connection: test setup/cleanup only. FORCE RLS still applies to it."""
    engine = create_async_engine(_owner_url(), poolclass=NullPool)
    yield engine
    await engine.dispose()


# M7: the inactive system user seeded by migration 0014 (the custody actor of purges, RT12)
# comes back after every truncation, as on a migrated database.
_SYSTEM_USER = text(
    "INSERT INTO users (id, email, password_hash, display_name, is_active) VALUES "
    "(:id, :email, '!unusable:retention-system-user', 'Retention (system)', false)"
)


async def _reset(owner_engine: AsyncEngine) -> None:
    tables = ", ".join(Base.metadata.tables)
    async with owner_engine.begin() as conn:
        # TRUNCATE bypasses row-level append-only triggers: test database only.
        await conn.execute(text(f"TRUNCATE TABLE {tables} CASCADE"))
        await conn.execute(
            _SYSTEM_USER, {"id": RETENTION_SYSTEM_USER_ID, "email": RETENTION_SYSTEM_USER_EMAIL}
        )
    await get_redis().flushdb()


@pytest_asyncio.fixture(scope="session", autouse=True, loop_scope="session")
async def _session_state(
    _migrated_test_database: None, owner_engine: AsyncEngine
) -> AsyncIterator[None]:
    # Start clean even if a previous run was interrupted before its teardown. The MinIO test
    # buckets are shared by every lane: only this process's objects are ever removed (M7
    # phase 11, tests/storage_helpers.py), never a whole bucket.
    await _reset(owner_engine)
    purge_owned()
    yield
    purge_owned()
    forget_owned_orgs()
    # Uploads queue analyses for real (only test_analysis.py captures dispatch); drop the
    # ones no test worker consumed so the broker does not grow across runs.
    purge_test_queues()
    await get_engine().dispose()


@pytest.fixture(scope="module", autouse=True)
def _owned_objects(_session_state: None) -> Iterator[None]:
    """After each module: remove the objects of the orgs it created (lane-safe)."""
    yield
    purge_owned()
    forget_owned_orgs()


@pytest_asyncio.fixture(autouse=True, loop_scope="session")
async def _clean_state(owner_engine: AsyncEngine, _session_state: None) -> AsyncIterator[None]:
    yield
    await _reset(owner_engine)
