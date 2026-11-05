"""Report stored object versions that no row records (report-only, deletes nothing).

Two buckets are compared with their rows:

- the evidence bucket (`MINIO_BUCKET`) with `evidence.storage_key / storage_version_id`;
- the report bucket (`REPORTS_BUCKET`, M6) with the snapshot of every `report_versions` row
  (`object_key / object_version_id`) and the artifact of every render that recorded one
  (`{org}/{report}/{version}/{render}.{format}` and `report_renders.object_version_id`).

An orphan can appear if the API process dies between storing an upload and committing its
records, when a finalize fails after its snapshot put (RT14, logged by the API as "orphan
report snapshot"), or when a renderer uploaded an artifact that ingest refused (or has not
ingested yet: a render still `running` shows its artifact here until it is recorded). Review
the output before removing anything by hand (versions may be retention-locked).

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
from typing import Any

from sqlalchemy import TextClause, text
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine

from app.core.clients import get_minio
from app.core.config import get_settings

Version = tuple[str, str]

EVIDENCE_RECORDS = text("SELECT storage_key, storage_version_id FROM evidence")
# Snapshots, then render artifacts. The render key is the one dispatch.render_key derives
# (ingest re-derives it too); a render without an object version recorded nothing.
REPORT_RECORDS = text(
    "SELECT object_key, object_version_id FROM report_versions "
    "UNION ALL "
    "SELECT v.organization_id::text || '/' || v.report_id::text || '/' || v.version::text "
    "|| '/' || r.id::text || '.' || r.format, r.object_version_id "
    "FROM report_renders r JOIN report_versions v "
    "ON v.id = r.version_id AND v.organization_id = r.organization_id "
    "WHERE r.object_version_id IS NOT NULL"
)


async def stored_versions(bucket: str, prefix: str = "") -> set[Version]:
    def _list() -> set[Version]:
        objects = get_minio().list_objects(
            bucket, prefix=prefix or None, recursive=True, include_version=True
        )
        return {
            (o.object_name, o.version_id)
            for o in objects
            if not o.is_delete_marker and o.object_name and o.version_id
        }

    return await asyncio.to_thread(_list)


async def recorded_versions(conn: AsyncConnection, query: TextClause) -> set[Version]:
    rows = await conn.execute(query)
    return {(str(key), str(version)) for key, version in rows}


def compare(bucket: str, stored: set[Version], recorded: set[Version]) -> dict[str, Any]:
    return {
        "bucket": bucket,
        "orphaned_versions": [{"key": k, "version_id": v} for k, v in sorted(stored - recorded)],
        "missing_content": [{"key": k, "version_id": v} for k, v in sorted(recorded - stored)],
    }


async def main() -> int:
    settings = get_settings()
    targets = ((settings.minio_bucket, EVIDENCE_RECORDS), (settings.reports_bucket, REPORT_RECORDS))
    engine = create_async_engine(settings.database_url)
    results: list[dict[str, Any]] = []
    try:
        async with engine.connect() as conn:
            # Fail loudly instead of reporting every object as orphaned when RLS hides rows.
            await conn.execute(text("SET row_security = off"))
            for bucket, query in targets:
                recorded = await recorded_versions(conn, query)
                results.append(compare(bucket, await stored_versions(bucket), recorded))
    finally:
        await engine.dispose()
    json.dump({"buckets": results}, sys.stdout, indent=2)
    sys.stdout.write("\n")
    found = any(r["orphaned_versions"] or r["missing_content"] for r in results)
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
