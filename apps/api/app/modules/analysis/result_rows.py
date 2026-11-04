"""Batched inserts of a validated result stream (inside the caller's transaction).

Postgres refuses COPY into tables with row-level security, so rows go in as batched
multi-row executemany INSERTs through the RLS-bound session. The stream is re-read from the
local file in batches (parsed in a worker thread), so memory stays bounded by one batch
(`max_lines` records or `max_bytes` of raw lines, whichever comes first) no matter how many
records the result holds or how long its lines are.
"""

import uuid
from collections import Counter, defaultdict
from collections.abc import Callable, Iterator
from typing import Any

import anyio
from sqlalchemy import Table, insert
from sqlalchemy.ext.asyncio import AsyncSession

Batch = dict[Table, list[dict[str, Any]]]
# (validated record) -> (table, row without the organization/job scope)
RowBuilder = Callable[[Any], tuple[Table, dict[str, Any]]]
# (records with their raw line size, scope, rows written per kind) -> next batch
BatchMaker = Callable[[Iterator[tuple[Any, int]], dict[str, Any], Counter[str]], Batch]


def next_batch(
    records: Iterator[tuple[Any, int]],
    scope: dict[str, Any],
    written: Counter[str],
    to_row: RowBuilder,
    *,
    max_lines: int,
    max_bytes: int,
) -> Batch:
    """Parse records into rows grouped by table until a batch cap is hit (worker thread)."""
    batch: Batch = defaultdict(list)
    size = 0
    for count, (record, line_bytes) in enumerate(records, start=1):
        table, row = to_row(record)
        batch[table].append({**row, **scope})
        written[record.kind] += 1
        size += line_bytes
        if count >= max_lines or size >= max_bytes:
            break
    return batch


async def insert_batches(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    records: Iterator[tuple[Any, int]],
    make_batch: BatchMaker,
) -> Counter[str]:
    """Insert every record; returns the rows written per record kind."""
    written: Counter[str] = Counter()
    scope = {"organization_id": org_id, "job_id": job_id}
    while batch := await anyio.to_thread.run_sync(make_batch, records, scope, written):
        for table, rows in batch.items():
            await session.execute(insert(table), rows)  # executemany (pipelined by asyncpg)
    return written
