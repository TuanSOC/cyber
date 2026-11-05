"""The correlation indexer (M7; frozen signature, phase 4 implements it).

Called by the trusted beat task `correlation.index_pending` on the ingest worker (a solo pool
shared with result ingest and the reaper, RT19): each tick takes at most `limit` succeeded jobs
without a `correlation_job_state` row and stops after `CORRELATION_INDEX_BUDGET_S`. The same
task backfills the history; `app/scripts/backfill_correlation.py` does it for large installs.
"""


async def index_pending(limit: int) -> int:
    """Index up to `limit` pending jobs; returns how many were indexed (phase 1: none)."""
    return 0
