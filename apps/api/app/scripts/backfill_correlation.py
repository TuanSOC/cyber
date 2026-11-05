"""Index the correlation keys of every succeeded job that has none yet (M7 phase 4).

The beat task `correlation.index_pending` already backfills the history, a few jobs per
minute (RT19: at most `CORRELATION_INDEX_BATCH_JOBS` jobs and `CORRELATION_INDEX_BUDGET_S`
per tick, because the ingest worker is a solo pool shared with result ingest and the reaper).
Large installs run this once instead, as a one-off container next to the running stack, never
inside the ingest worker:

    docker compose run --rm --no-deps ingest-worker \
        uv run python -m app.scripts.backfill_correlation [--batch 20]

It loops `indexer.index_pending` until a pass indexes nothing. It is idempotent and
restart-safe (each job is one transaction, ON CONFLICT DO NOTHING), so it may run while the
beat task does: they never index a job twice. The budget per pass follows
`CORRELATION_INDEX_BUDGET_S` (raise it in the container's env for a faster backfill).
Prints one JSON line with the totals; no observable value is ever printed.
"""

import argparse
import asyncio
import json
import sys
import time

import app.models  # noqa: F401  (register every mapper before the first query)
from app.core.db import get_engine
from app.modules.correlation.indexer import index_pending

DEFAULT_BATCH = 20


async def backfill(batch: int) -> int:
    total = 0
    while True:
        indexed = await index_pending(batch)
        if indexed == 0:
            return total
        total += indexed
        print(json.dumps({"indexed": total}), file=sys.stderr, flush=True)


async def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--batch", type=int, default=DEFAULT_BATCH, help="jobs per pass (1..500)")
    args = parser.parse_args(argv)
    if not 1 <= args.batch <= 500:
        parser.error("--batch must be between 1 and 500")
    started = time.monotonic()
    try:
        total = await backfill(args.batch)
    finally:
        await get_engine().dispose()
    print(json.dumps({"indexed": total, "seconds": round(time.monotonic() - started, 1)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
