"""The correlation indexer (M7 phase 4; frozen signature from phase 1).

Called by the trusted beat task `correlation.index_pending` on the ingest worker (a solo pool
shared with result ingest and the reaper, RT19): each tick takes at most `limit` succeeded
jobs without a `correlation_job_state` row and stops after `CORRELATION_INDEX_BUDGET_S` (at
least one job per tick, so a slow job never stalls the backlog). The same task backfills the
history; `app/scripts/backfill_correlation.py` loops it for large installs (one-off container).

Discovery: the orgs come from the non-tenant `analysis_job_index` (system session; the
reaper's pattern). `correlation_job_state` is a tenant table (FORCE RLS, no system read), so
the pending jobs are found per org in a `tenant_session(org)`, rotating the org order between
ticks so one org's backlog never starves the others.

Per job, in one tenant transaction:
- sources: the evidence's sha256 (`evidence_hashes`), the static sample's md5 / sha1 / sha256
  (`malware_samples`) and every `iocs` row (JA3 / JA3S / cert hashes are IOC rows already,
  RT8); `network_records` is not read;
- keys from `normalize.correlation_key` (M6 `normalize_item`), one per (kind, key): the first
  source wins, the times widen to the earliest first / latest last seen;
- the cap `CORRELATION_MAX_KEYS_PER_JOB` keeps the first keys in a deterministic order (the
  hashes, then hash and JA3 IOC types, then `iocs.count` desc, then value) and records
  `truncated`;
- `correlation_keys` and the `correlation_job_state` row are inserted with ON CONFLICT DO
  NOTHING in the same transaction: idempotent and restart-safe. Keys are never purged (RT9),
  so a job is indexed exactly once.
"""

import logging
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import case, exists, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.tenancy import tenant_session
from app.modules.analysis.models import AnalysisJob, AnalysisJobIndex, AnalysisStatus
from app.modules.correlation.models import CorrelationJobState, CorrelationKey
from app.modules.correlation.normalize import NOT_INDEXED, correlation_key
from app.modules.evidence.models import Evidence, EvidenceHash, HashAlgorithm
from app.modules.pcap_analysis.models import Ioc
from app.modules.static_analysis.models import MalwareSample

log = logging.getLogger(__name__)

# IOC types sorted first under the cap (hashes and TLS fingerprints: the strongest pivots).
PRIORITY_IOC_TYPES = ("file_md5", "file_sha1", "file_sha256", "ja3", "ja3s", "cert_sha256")
INSERT_CHUNK = 1_000
STREAM_CHUNK = 2_000

# Process-local rotation of the org order (fairness between ticks; no correctness role).
_rotation = 0


@dataclass
class _Key:
    kind: str
    key: str
    value_norm: str
    source_table: str
    source_id: str
    first_seen: datetime | None
    last_seen: datetime | None


@dataclass
class _Collected:
    keys: dict[tuple[str, str], _Key]
    truncated: bool = False
    skipped: int = 0


def _earliest(a: datetime | None, b: datetime | None) -> datetime | None:
    return b if a is None else a if b is None else min(a, b)


def _latest(a: datetime | None, b: datetime | None) -> datetime | None:
    return b if a is None else a if b is None else max(a, b)


def _add(
    out: _Collected,
    cap: int,
    ioc_type: str,
    raw: str,
    source: tuple[str, str],
    seen: tuple[datetime | None, datetime | None],
) -> bool:
    """Add one source value; False once the cap is reached and this value is a new key."""
    normalized = correlation_key(ioc_type, raw)
    if normalized is None:
        out.skipped += 1
        return True
    kind, key, value_norm = normalized
    existing = out.keys.get((kind, key))
    if existing is not None:
        existing.first_seen = _earliest(existing.first_seen, seen[0])
        existing.last_seen = _latest(existing.last_seen, seen[1])
        return True
    if len(out.keys) >= cap:
        out.truncated = True
        return False
    out.keys[(kind, key)] = _Key(kind, key, value_norm, source[0], source[1], seen[0], seen[1])
    return True


async def _collect(session: AsyncSession, job: AnalysisJob, cap: int) -> _Collected:
    out = _Collected(keys={})
    job_seen = (job.started_at or job.created_at, job.finished_at or job.started_at)

    evidence_hashes = await session.execute(
        select(EvidenceHash.id, EvidenceHash.value).where(
            EvidenceHash.organization_id == job.organization_id,
            EvidenceHash.evidence_id == job.evidence_id,
            EvidenceHash.algorithm == HashAlgorithm.SHA256,
        )
    )
    for hash_id, value in evidence_hashes:
        _add(out, cap, "sha256", value, ("evidence_hashes", str(hash_id)), job_seen)

    samples = await session.execute(
        select(MalwareSample).where(
            MalwareSample.organization_id == job.organization_id,
            MalwareSample.job_id == job.id,
        )
    )
    for sample in samples.scalars():
        for kind, value in (("sha256", sample.sha256), ("sha1", sample.sha1), ("md5", sample.md5)):
            _add(out, cap, kind, value, ("malware_samples", str(sample.id)), job_seen)

    priority = case((Ioc.type.in_(PRIORITY_IOC_TYPES), 0), else_=1)
    stmt = (
        select(Ioc.id, Ioc.type, Ioc.value, Ioc.first_seen, Ioc.last_seen)
        .where(
            Ioc.organization_id == job.organization_id,
            Ioc.job_id == job.id,
            Ioc.type.not_in(tuple(NOT_INDEXED)),
        )
        .order_by(priority, Ioc.count.desc(), Ioc.value, Ioc.id)
        .execution_options(yield_per=STREAM_CHUNK)
    )
    result = await session.stream(stmt)
    try:
        async for ioc_id, ioc_type, value, first_seen, last_seen in result:
            if not _add(out, cap, ioc_type, value, ("iocs", str(ioc_id)), (first_seen, last_seen)):
                break
    finally:
        await result.close()
    return out


async def index_job(org_id: uuid.UUID, job_id: uuid.UUID) -> bool:
    """Index one job of `org_id` (org from the system index, never from a request). False
    when it is already indexed, gone, or not succeeded."""
    cap = get_settings().correlation_max_keys_per_job
    async with tenant_session(org_id, None) as session:
        if await session.get(CorrelationJobState, job_id) is not None:
            return False
        row = (
            await session.execute(
                select(AnalysisJob, Evidence.investigation_id)
                .join(
                    Evidence,
                    (Evidence.id == AnalysisJob.evidence_id)
                    & (Evidence.organization_id == AnalysisJob.organization_id),
                )
                .where(AnalysisJob.id == job_id, AnalysisJob.organization_id == org_id)
            )
        ).one_or_none()
        if row is None or row[0].status is not AnalysisStatus.SUCCEEDED:
            return False
        job, investigation_id = row
        collected = await _collect(session, job, cap)
        rows: list[dict[str, Any]] = [
            {
                "id": uuid.uuid4(),
                "organization_id": org_id,
                "investigation_id": investigation_id,
                "evidence_id": job.evidence_id,
                "job_id": job.id,
                "kind": k.kind,
                "key": k.key,
                "value_norm": k.value_norm,
                "source_table": k.source_table,
                "source_id": k.source_id,
                "first_seen": k.first_seen,
                "last_seen": k.last_seen,
            }
            for k in collected.keys.values()
        ]
        insert_keys = pg_insert(CorrelationKey).on_conflict_do_nothing(
            index_elements=["job_id", "kind", "key"]
        )
        for start in range(0, len(rows), INSERT_CHUNK):
            await session.execute(insert_keys, rows[start : start + INSERT_CHUNK])
        await session.execute(
            pg_insert(CorrelationJobState)
            .values(
                job_id=job.id,
                organization_id=org_id,
                keys=len(rows),
                truncated=collected.truncated,
            )
            .on_conflict_do_nothing(index_elements=["job_id"])
        )
    log.debug(
        "correlation: job %s indexed (%d keys, %d skipped, truncated=%s)",
        job_id,
        len(rows),
        collected.skipped,
        collected.truncated,
    )
    return True


async def _orgs_with_succeeded_jobs() -> list[uuid.UUID]:
    async with tenant_session(None, None) as session:
        orgs = await session.execute(
            select(AnalysisJobIndex.organization_id)
            .where(AnalysisJobIndex.status == AnalysisStatus.SUCCEEDED)
            .distinct()
            .order_by(AnalysisJobIndex.organization_id)
        )
        return list(orgs.scalars())


async def _pending_in(org_id: uuid.UUID, limit: int) -> list[uuid.UUID]:
    async with tenant_session(org_id, None) as session:
        indexed = exists().where(CorrelationJobState.job_id == AnalysisJobIndex.job_id)
        jobs = await session.execute(
            select(AnalysisJobIndex.job_id)
            .where(
                AnalysisJobIndex.organization_id == org_id,
                AnalysisJobIndex.status == AnalysisStatus.SUCCEEDED,
                ~indexed,
            )
            .order_by(AnalysisJobIndex.job_id)
            .limit(limit)
        )
        return list(jobs.scalars())


async def index_pending(limit: int) -> int:
    """Index up to `limit` pending jobs within the tick budget; returns how many were indexed."""
    global _rotation
    if limit < 1:
        return 0
    deadline = time.monotonic() + get_settings().correlation_index_budget_s
    orgs = await _orgs_with_succeeded_jobs()
    if not orgs:
        return 0
    start = _rotation % len(orgs)
    _rotation += 1
    indexed = 0
    attempted = 0
    for org_id in (*orgs[start:], *orgs[:start]):
        if attempted >= limit or (attempted and time.monotonic() >= deadline):
            break
        for job_id in await _pending_in(org_id, limit - attempted):
            if attempted and time.monotonic() >= deadline:
                break
            attempted += 1
            try:
                if await index_job(org_id, job_id):
                    indexed += 1
            except Exception as exc:  # one bad job must not stall the others (no values logged)
                log.error("correlation: indexing job %s failed (%s)", job_id, type(exc).__name__)
    return indexed
