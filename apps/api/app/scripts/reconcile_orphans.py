"""Report evidence object versions that have no evidence row (report-only, deletes nothing).

An orphan can appear if the API process dies between storing an upload and committing its
records. Review the output before removing anything by hand (versions may be retention-locked).

Needs a role that bypasses RLS: the API and owner roles are bound by FORCE ROW LEVEL SECURITY,
so the query fails loudly for them. Run inside the api container (it has the MinIO config)
with the Postgres superuser URL:

    docker compose exec \
        -e DATABASE_URL="postgresql+asyncpg://postgres:<POSTGRES_PASSWORD>@postgres:5432/cyberlab" \
        api uv run python -m app.scripts.reconcile_orphans
"""

import asyncio
import json
import sys

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.core.clients import get_minio
from app.core.config import get_settings


async def stored_versions() -> set[tuple[str, str]]:
    def _list() -> set[tuple[str, str]]:
        objects = get_minio().list_objects(
            get_settings().minio_bucket, recursive=True, include_version=True
        )
        return {(o.object_name, o.version_id) for o in objects if not o.is_delete_marker}

    return await asyncio.to_thread(_list)


async def recorded_versions() -> set[tuple[str, str]]:
    engine = create_async_engine(get_settings().database_url)
    try:
        async with engine.connect() as conn:
            # Fail loudly instead of reporting every object as orphaned when RLS hides rows.
            await conn.execute(text("SET row_security = off"))
            rows = await conn.execute(text("SELECT storage_key, storage_version_id FROM evidence"))
            return {(key, version) for key, version in rows}
    finally:
        await engine.dispose()


async def main() -> int:
    stored = await stored_versions()
    recorded = await recorded_versions()
    orphans = sorted(stored - recorded)
    missing = sorted(recorded - stored)
    json.dump(
        {
            "bucket": get_settings().minio_bucket,
            "orphaned_versions": [{"key": k, "version_id": v} for k, v in orphans],
            "missing_content": [{"key": k, "version_id": v} for k, v in missing],
        },
        sys.stdout,
        indent=2,
    )
    sys.stdout.write("\n")
    return 1 if orphans or missing else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
