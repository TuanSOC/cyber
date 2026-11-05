"""Correlation read queries (M7 phase 4). Every query runs in the caller's tenant session
(RLS) and also filters `organization_id` explicitly, so it uses `(organization_id, kind, key)`
and never crosses an org. Counts only, no scores."""

import uuid
from collections.abc import Sequence
from functools import cache
from typing import Any

from sqlalchemy import RowMapping, TextClause, text
from sqlalchemy.ext.asyncio import AsyncSession


@cache
def _job_keys_sql(by_kind: bool, include_unique: bool) -> TextClause:
    """The job pivot: the job's keys (by default only those at least one other job of the
    org shares), paged. The optional branches come from a closed set of fragments."""
    kind = "AND kind = :kind" if by_kind else ""
    shared = "" if include_unique else "WHERE jobs > 1"
    return text(
        f"""
        WITH mine AS (
          SELECT kind, key, value_norm, source_table, source_id FROM correlation_keys
          WHERE organization_id = :org AND job_id = :job {kind}
        ), agg AS (
          SELECT m.kind, m.key, m.value_norm, m.source_table, m.source_id,
                 count(*) AS jobs,
                 count(DISTINCT ck.investigation_id)
                   FILTER (WHERE ck.investigation_id <> :inv) AS other_cases,
                 min(ck.first_seen) AS first_seen,
                 max(ck.last_seen) AS last_seen
          FROM mine m
          JOIN correlation_keys ck
            ON ck.organization_id = :org AND ck.kind = m.kind AND ck.key = m.key
          GROUP BY m.kind, m.key, m.value_norm, m.source_table, m.source_id
        )
        SELECT kind, key, value_norm, jobs, jobs - 1 AS other_jobs, other_cases,
               first_seen, last_seen,
               CASE WHEN source_table = 'iocs' THEN source_id END AS ioc_id
        FROM agg
        {shared}
        ORDER BY other_cases DESC, kind, value_norm, key
        LIMIT :limit OFFSET :offset
        """  # noqa: S608 (fixed SQL fragments only)
    )


# At most `per_key` other cases per key, most recent first.
_TOP_CASES = text(
    """
    SELECT kind, key, investigation_id, case_number, title, jobs, last_seen FROM (
      SELECT s.kind, s.key, s.investigation_id, i.case_number, i.title, s.jobs, s.last_seen,
             row_number() OVER (
               PARTITION BY s.kind, s.key
               ORDER BY s.last_seen DESC NULLS LAST, s.investigation_id
             ) AS rn
      FROM (
        SELECT ck.kind, ck.key, ck.investigation_id,
               count(*) AS jobs, max(ck.last_seen) AS last_seen
        FROM correlation_keys ck
        JOIN unnest(CAST(:kinds AS varchar[]), CAST(:keys AS varchar[])) AS want(kind, key)
          ON ck.kind = want.kind AND ck.key = want.key
        WHERE ck.organization_id = :org AND ck.investigation_id <> :inv
        GROUP BY ck.kind, ck.key, ck.investigation_id
      ) s
      JOIN investigations i ON i.id = s.investigation_id AND i.organization_id = :org
    ) ranked
    WHERE rn <= :per_key
    ORDER BY kind, key, rn
    """
)

_KEY_STATS = text(
    """
    SELECT count(*) AS jobs, count(DISTINCT investigation_id) AS cases,
           min(first_seen) AS first_seen, max(last_seen) AS last_seen
    FROM correlation_keys
    WHERE organization_id = :org AND kind = :kind AND key = :key
    """
)

_OCCURRENCES = text(
    """
    SELECT ck.job_id, j.analyzer, ck.investigation_id, i.case_number, i.title,
           ck.evidence_id, e.original_filename, ck.first_seen, ck.last_seen
    FROM correlation_keys ck
    JOIN analysis_jobs j ON j.id = ck.job_id AND j.organization_id = ck.organization_id
    JOIN investigations i
      ON i.id = ck.investigation_id AND i.organization_id = ck.organization_id
    JOIN evidence e ON e.id = ck.evidence_id AND e.organization_id = ck.organization_id
    WHERE ck.organization_id = :org AND ck.kind = :kind AND ck.key = :key
    ORDER BY ck.last_seen DESC NULLS LAST, j.created_at DESC, ck.job_id
    LIMIT :limit
    """
)

# Related cases: the case's distinct keys and how many jobs of the org carry each one.
_CASE_KEYS = """
    WITH mine AS (
      SELECT DISTINCT kind, key FROM correlation_keys
      WHERE organization_id = :org AND investigation_id = :inv
    ), freq AS (
      SELECT m.kind, m.key, count(*) AS jobs
      FROM mine m
      JOIN correlation_keys ck
        ON ck.organization_id = :org AND ck.kind = m.kind AND ck.key = m.key
      GROUP BY m.kind, m.key
    )
"""

_RELATED = text(
    _CASE_KEYS  # noqa: S608 (fixed SQL fragments only)
    + """
    , shared AS (
      SELECT ck.investigation_id, ck.kind, ck.key, min(ck.value_norm) AS value_norm,
             max(ck.last_seen) AS last_seen
      FROM freq f
      JOIN correlation_keys ck
        ON ck.organization_id = :org AND ck.kind = f.kind AND ck.key = f.key
      WHERE f.jobs <= :common AND ck.investigation_id <> :inv
      GROUP BY ck.investigation_id, ck.kind, ck.key
    ), ranked AS (
      SELECT investigation_id, count(*) AS shared_keys, max(last_seen) AS last_seen
      FROM shared
      GROUP BY investigation_id
      ORDER BY shared_keys DESC, last_seen DESC NULLS LAST, investigation_id
      LIMIT :limit
    )
    SELECT r.investigation_id, i.case_number, i.title, i.status, r.shared_keys, r.last_seen,
           (SELECT jsonb_object_agg(k.kind, k.n)
              FROM (SELECT s.kind, count(*) AS n FROM shared s
                    WHERE s.investigation_id = r.investigation_id GROUP BY s.kind) k
           ) AS kinds,
           (SELECT jsonb_agg(jsonb_build_object('kind', x.kind, 'key', x.key,
                                                'value', x.value_norm) ORDER BY x.rn)
              FROM (SELECT s.kind, s.key, s.value_norm,
                           row_number() OVER (
                             ORDER BY s.last_seen DESC NULLS LAST, s.kind, s.value_norm, s.key
                           ) AS rn
                      FROM shared s WHERE s.investigation_id = r.investigation_id) x
             WHERE x.rn <= :samples
           ) AS samples
    FROM ranked r
    JOIN investigations i ON i.id = r.investigation_id AND i.organization_id = :org
    ORDER BY r.shared_keys DESC, r.last_seen DESC NULLS LAST, r.investigation_id
    """
)

_COMMON_EXCLUDED = text(_CASE_KEYS + "SELECT count(*) FROM freq WHERE jobs > :common")  # noqa: S608

# Stored threat intel answers for one key (count only; `(organization_id, ioc_key, ...)`).
_TI_COUNT = text(
    """
    SELECT count(*) FROM ti_results
    WHERE organization_id = :org AND ioc_key = :key AND ioc_type = :kind
    """
)

# The org's IOC collections holding the key (items not removed).
_COLLECTIONS = text(
    """
    SELECT c.id, c.investigation_id, i.case_number, c.name, c.archived_at IS NOT NULL AS archived,
           count(*) OVER () AS total
    FROM ioc_collections c
    JOIN investigations i ON i.id = c.investigation_id AND i.organization_id = c.organization_id
    WHERE c.organization_id = :org
      AND EXISTS (
        SELECT 1 FROM ioc_collection_items it
        WHERE it.organization_id = :org AND it.collection_id = c.id
          AND it.ioc_key = :key AND it.ioc_type = :kind AND it.removed_at IS NULL
      )
    ORDER BY c.updated_at DESC, c.id
    LIMIT :limit
    """
)


async def job_keys(
    session: AsyncSession,
    org_id: uuid.UUID,
    job_id: uuid.UUID,
    inv_id: uuid.UUID,
    limit: int,
    *,
    kind: str | None = None,
    include_unique: bool = False,
    offset: int = 0,
) -> Sequence[RowMapping]:
    params: dict[str, Any] = {
        "org": org_id,
        "job": job_id,
        "inv": inv_id,
        "limit": limit,
        "offset": offset,
    }
    if kind is not None:
        params["kind"] = kind
    stmt = _job_keys_sql(kind is not None, include_unique)
    return (await session.execute(stmt, params)).mappings().all()


async def top_cases(
    session: AsyncSession,
    org_id: uuid.UUID,
    inv_id: uuid.UUID,
    keys: Sequence[tuple[str, str]],
    per_key: int,
) -> dict[tuple[str, str], list[RowMapping]]:
    out: dict[tuple[str, str], list[RowMapping]] = {}
    if not keys:
        return out
    params: dict[str, Any] = {
        "org": org_id,
        "inv": inv_id,
        "kinds": [k for k, _ in keys],
        "keys": [k for _, k in keys],
        "per_key": per_key,
    }
    for row in (await session.execute(_TOP_CASES, params)).mappings():
        out.setdefault((row["kind"], row["key"]), []).append(row)
    return out


async def key_stats(session: AsyncSession, org_id: uuid.UUID, kind: str, key: str) -> RowMapping:
    params = {"org": org_id, "kind": kind, "key": key}
    return (await session.execute(_KEY_STATS, params)).mappings().one()


async def occurrences(
    session: AsyncSession, org_id: uuid.UUID, kind: str, key: str, limit: int
) -> Sequence[RowMapping]:
    params = {"org": org_id, "kind": kind, "key": key, "limit": limit}
    return (await session.execute(_OCCURRENCES, params)).mappings().all()


async def ti_result_count(session: AsyncSession, org_id: uuid.UUID, kind: str, key: str) -> int:
    params = {"org": org_id, "kind": kind, "key": key}
    return int((await session.execute(_TI_COUNT, params)).scalar_one())


async def collections(
    session: AsyncSession, org_id: uuid.UUID, kind: str, key: str, limit: int
) -> tuple[Sequence[RowMapping], int]:
    params = {"org": org_id, "kind": kind, "key": key, "limit": limit}
    rows = (await session.execute(_COLLECTIONS, params)).mappings().all()
    return rows, int(rows[0]["total"]) if rows else 0


async def related(
    session: AsyncSession,
    org_id: uuid.UUID,
    inv_id: uuid.UUID,
    common: int,
    limit: int,
    samples: int,
) -> tuple[Sequence[RowMapping], int]:
    params = {"org": org_id, "inv": inv_id, "common": common}
    rows = (
        (await session.execute(_RELATED, {**params, "limit": limit, "samples": samples}))
        .mappings()
        .all()
    )
    excluded = (await session.execute(_COMMON_EXCLUDED, params)).scalar_one()
    return rows, int(excluded)
