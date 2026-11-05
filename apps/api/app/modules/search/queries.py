"""Per-type search queries (M7 phase 4): Postgres FTS (`simple`) and pg_trgm only.

The expressions match the phase-1 index expressions of migration 0014 exactly
(`tests/integration/test_search.py` runs EXPLAIN and asserts index use), otherwise Postgres
silently falls back to sequential scans:
- `ix_investigations_search_fts`, `ix_analysis_findings_search_fts`:
  `to_tsvector('simple'::regconfig, coalesce(title, '') || ' ' || coalesce(description, ''))`;
- `ix_network_alerts_search_fts`: `to_tsvector('simple'::regconfig, coalesce(signature, ''))`;
- `ix_analyst_note_versions_search_fts`: `to_tsvector('simple'::regconfig, coalesce(body, ''))`;
- trigram (`gin_trgm_ops`): `investigations (case_number::text)`, `evidence
  (original_filename)`, `correlation_keys (value_norm)`.

The SQL text is fixed: the query only ever travels as a bind parameter, and optional branches
are chosen from a closed set of fragments (never built from user text). Every query filters
`organization_id` explicitly on top of RLS.
"""

from dataclasses import dataclass
from typing import Any

from sqlalchemy import TextClause, text

FTS_CASE = (
    "to_tsvector('simple'::regconfig, coalesce(i.title, '') || ' ' || coalesce(i.description, ''))"
)
FTS_FINDING = (
    "to_tsvector('simple'::regconfig, coalesce(f.title, '') || ' ' || coalesce(f.description, ''))"
)
FTS_ALERT = "to_tsvector('simple'::regconfig, coalesce(a.signature, ''))"
FTS_NOTE = "to_tsvector('simple'::regconfig, coalesce(v.body, ''))"
TSQUERY = "websearch_to_tsquery('simple'::regconfig, :q)"
TRGM_OBSERVABLE = "(ck.value_norm % :q OR ck.value_norm ILIKE :like ESCAPE '\\')"
TRGM_EVIDENCE = "(e.original_filename % :q OR e.original_filename ILIKE :like ESCAPE '\\')"
CASE_NUMBER_LIKE = "(i.case_number::text) LIKE :number_like"
# Candidate rows ranked before the observables are grouped by key.
OBSERVABLE_CANDIDATES = 2_000

# --- observables ---------------------------------------------------------------------------

OBSERVABLE_EXACT = text(
    """
    SELECT DISTINCT ck.kind, ck.key
    FROM correlation_keys ck
    JOIN unnest(CAST(:kinds AS varchar[]), CAST(:keys AS varchar[])) AS want(kind, key)
      ON ck.kind = want.kind AND ck.key = want.key
    WHERE ck.organization_id = :org
    """
)

OBSERVABLE_TRIGRAM = text(
    f"""
    SELECT kind, key, max(sim) AS sim, min(value_norm) AS value_norm FROM (
      SELECT ck.kind, ck.key, ck.value_norm, similarity(ck.value_norm, :q) AS sim
      FROM correlation_keys ck
      WHERE ck.organization_id = :org
        AND {TRGM_OBSERVABLE}
      ORDER BY sim DESC, ck.value_norm, ck.kind
      LIMIT {OBSERVABLE_CANDIDATES}
    ) m
    GROUP BY kind, key
    ORDER BY sim DESC, value_norm, kind, key
    LIMIT :limit
    """  # noqa: S608
)

# The latest occurrence of each selected key (its case, job and deep link) and its job count.
OBSERVABLE_DETAILS = text(
    """
    SELECT DISTINCT ON (ck.kind, ck.key)
           ck.kind, ck.key, ck.value_norm, ck.job_id, ck.investigation_id, ck.evidence_id,
           ck.last_seen, j.analyzer, i.case_number, i.tlp,
           count(*) OVER (PARTITION BY ck.kind, ck.key) AS jobs
    FROM correlation_keys ck
    JOIN unnest(CAST(:kinds AS varchar[]), CAST(:keys AS varchar[])) AS want(kind, key)
      ON ck.kind = want.kind AND ck.key = want.key
    JOIN analysis_jobs j ON j.id = ck.job_id AND j.organization_id = ck.organization_id
    JOIN investigations i
      ON i.id = ck.investigation_id AND i.organization_id = ck.organization_id
    WHERE ck.organization_id = :org
    ORDER BY ck.kind, ck.key, ck.last_seen DESC NULLS LAST, j.created_at DESC, ck.job_id
    """
)

# --- the other types -----------------------------------------------------------------------


@dataclass(frozen=True)
class CaseQuery:
    fts: bool
    number: bool
    number_like: bool


def case_query(plan: CaseQuery) -> TextClause:
    branches = []
    if plan.fts:
        branches.append(f"{FTS_CASE} @@ {TSQUERY}")
    if plan.number:
        branches.append("i.case_number = :number")
    if plan.number_like:
        branches.append(CASE_NUMBER_LIKE)
    exact = "i.case_number = :number" if plan.number else "false"
    return text(
        f"""
        SELECT i.id, i.case_number, i.title, i.description, i.updated_at, i.tlp,
               ({exact}) AS exact
        FROM investigations i
        WHERE i.organization_id = :org AND ({" OR ".join(branches)})
        ORDER BY exact DESC, i.updated_at DESC, i.id
        LIMIT :limit OFFSET :offset
        """  # noqa: S608
    )


EVIDENCE = text(
    f"""
    SELECT e.id, e.original_filename, e.investigation_id, i.case_number, i.tlp, e.uploaded_at,
           similarity(e.original_filename, :q) AS sim
    FROM evidence e
    JOIN investigations i ON i.id = e.investigation_id AND i.organization_id = e.organization_id
    WHERE e.organization_id = :org
      AND {TRGM_EVIDENCE}
    ORDER BY sim DESC, e.uploaded_at DESC, e.id
    LIMIT :limit OFFSET :offset
    """  # noqa: S608
)

FINDING = text(
    f"""
    SELECT f.id, f.title, f.description, f.job_id, f.ts, j.analyzer, j.evidence_id,
           e.investigation_id, i.case_number, i.tlp
    FROM analysis_findings f
    JOIN analysis_jobs j ON j.id = f.job_id AND j.organization_id = f.organization_id
    JOIN evidence e ON e.id = j.evidence_id AND e.organization_id = j.organization_id
    JOIN investigations i ON i.id = e.investigation_id AND i.organization_id = e.organization_id
    WHERE f.organization_id = :org AND {FTS_FINDING} @@ {TSQUERY}
    ORDER BY f.ts DESC, f.id
    LIMIT :limit OFFSET :offset
    """  # noqa: S608
)

ALERT = text(
    f"""
    SELECT a.id, a.signature, a.category, a.job_id, a.ts, j.analyzer, j.evidence_id,
           e.investigation_id, i.case_number, i.tlp
    FROM network_alerts a
    JOIN analysis_jobs j ON j.id = a.job_id AND j.organization_id = a.organization_id
    JOIN evidence e ON e.id = j.evidence_id AND e.organization_id = j.organization_id
    JOIN investigations i ON i.id = e.investigation_id AND i.organization_id = e.organization_id
    WHERE a.organization_id = :org AND {FTS_ALERT} @@ {TSQUERY}
    ORDER BY a.ts DESC, a.id
    LIMIT :limit OFFSET :offset
    """  # noqa: S608
)

# The current version of non-deleted notes only.
NOTE = text(
    f"""
    SELECT n.id, n.investigation_id, i.case_number, i.tlp, v.body, v.created_at
    FROM analyst_note_versions v
    JOIN analyst_notes n
      ON n.id = v.note_id AND n.organization_id = v.organization_id
     AND n.current_version = v.version
    JOIN investigations i ON i.id = n.investigation_id AND i.organization_id = n.organization_id
    WHERE v.organization_id = :org AND n.deleted_at IS NULL AND {FTS_NOTE} @@ {TSQUERY}
    ORDER BY v.created_at DESC, n.id
    LIMIT :limit OFFSET :offset
    """  # noqa: S608
)


def keys_params(keys: list[tuple[str, str]]) -> dict[str, Any]:
    return {"kinds": [k for k, _ in keys], "keys": [k for _, k in keys]}
