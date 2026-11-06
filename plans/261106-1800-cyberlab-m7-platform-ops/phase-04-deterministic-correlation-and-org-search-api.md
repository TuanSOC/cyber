---
phase: 4
title: "Deterministic correlation and org search API"
status: pending
priority: P1
effort: "16h"
dependencies: [1]
---

# Phase 4: Deterministic correlation and org search API (group B, 2c, lane 4)

## Overview
The §4 `correlation` module and the §3 / §12 search, both on Postgres:
- a trusted indexer builds `correlation_keys` from every succeeded job: IOCs (JA3, JA3S and certificate hashes are already IOC rows), sample and evidence hashes;
- read routes answer "also seen in", key lookups and related cases inside one org;
- one search route covers observables, cases, evidence, findings, alerts and notes.

Deterministic, without AI or scores. The design is in plan.md "Correlation and search".

**Owns:**
- `app/modules/correlation/**` (after the stubs): `normalize.py`, `indexer.py`, `repository.py`, `service.py`, `router.py`;
- `app/modules/search/**` (after the stubs): `service.py`, `queries.py`, `router.py`;
- `app/scripts/backfill_correlation.py`;
- `tests/security/idor_cases_correlation.py`;
- `tests/integration/test_correlation_{indexer,reads,related}.py`, `test_search.py` and `test_search_perf.py`;
- `tests/unit/test_correlation_normalize.py`.

## Requirements
- **`normalize.py: correlation_key(ioc_type, raw) -> (kind, key, value_norm) | None` (RT8):**
  - **Delegate to M6 `ioc_collections.normalize.normalize_item(ioc_type, raw)`** (import, never edit). It already runs the M4 TI normalizer, keeps private IPs and internal names, maps `iocs.type` values (`ip`, `file_sha256`, …) to the M4 `IocType` (`ipv4` / `ipv6`, `sha256`, …), and keys the pcap-only types (`ja3`, `ja3s`, `cert_sha256`) with `opaque_key` on the trimmed value. `kind` = `Item.ioc_type`, `key` = `Item.ioc_key`: byte-identical to `ti_results.ioc_key` and `ioc_collection_items.ioc_key`. Tests assert both equalities on fixtures, including an IPv4, an IPv6 and a JA3 in mixed case.
  - **Not indexed:** `registry_key` and `file_path` (host-specific noise), and anything `normalize_item` returns as `Invalid` (counted, never raised).
  - Do **not** lowercase or otherwise re-normalize on top of `normalize_item`: any extra rule breaks the join.
- **Indexer** (`index_pending(limit)`, run by the ingest-worker beat task every 60 s, app role):
  - System lookup: `analysis_job_index` rows with `status = succeeded` and no `correlation_job_state` row. The index is not tenant data; follow the reaper's pattern to read it.
  - For each job (≤ `limit`, default 5, and within `CORRELATION_INDEX_BUDGET_S` 10 s per tick, because the ingest worker is a solo pool shared with result ingest and the reaper, RT19), in a `tenant_session(org)`:
    - read the `iocs` of the job (every type, JA3 / JA3S / `cert_sha256` included), `malware_samples` (md5, sha1, sha256) and the evidence's `evidence_hashes` sha256. `network_records` is not read (its JSON column is `details`, and JA3 is already an IOC row, RT8);
    - insert `correlation_keys` (`ON CONFLICT DO NOTHING`), carrying `investigation_id` and `evidence_id` from the job and evidence, `first_seen` / `last_seen` from the source row (or the job's times);
    - insert `correlation_job_state` (`keys` count) in the same transaction.
  - Per-job cap: `CORRELATION_MAX_KEYS_PER_JOB` (20 000). Past it, keep the first keys in a deterministic order (hash and JA3 kinds first, then by `iocs.count` desc, then value) and record `truncated` in the state.
  - Idempotent and restart-safe.
  - `backfill_correlation.py` loops `index_pending` until none remain, as a one-off `compose run` container (never inside the ingest worker). It is documented for big installs.
  - Keys are never purged by retention (RT9), so a job is indexed exactly once.
- **Reads** (`investigation.read`, RLS):
  - **`GET /analyses/{job}/correlations?kind=&cursor=`:** for each key of the job, its `source_ids` in this job (the `iocs` row ids, so the UI joins by id, RT8), `other_jobs` and `other_cases` counts, `first_seen` / `last_seen` across the org, `common` (other jobs > `CORRELATION_COMMON_KEY_JOBS`) and `top_cases` (≤ 5: id, case number, title, TLP, status). Paged by key; sort: shared-case count desc, then kind, then value. Keys seen nowhere else are omitted unless `include_unique=true`.
  - **`GET /correlations?kind=&value=`:** the server normalizes `value` (`422 search_query_invalid` when it does not normalize) and lists the jobs and cases that contain it (paged, newest first), with deep-link descriptors (pcap or static job tab and `ref`), plus the TI history count for IOC kinds (a join on `ti_results.ioc_key`, count only) and the collection memberships (`ioc_collection_items.ioc_key`).
  - **`GET /investigations/{inv}/related`:** other cases ranked by the number of distinct shared non-common keys (ties: the latest shared `last_seen`), ≤ 20, each with ≤ 5 sample shared keys. Archived cases are included and labelled.
  - **Purged jobs:** their keys stay (RT9): a closed case whose bytes were purged still correlates, and its deep links land on the kept IOC rows.
- **Search** (`POST /search` with body `{q, types, cursor}`, `investigation.read`; rate limit 30 / min / user, using `core/rate_limit.hit`). POST keeps the query out of every URL and access log (RT13); CSRF applies as on every POST:
  - **Input:** `q` is trimmed, 2–256 characters, with no control characters. `types` ⊆ `{observable, case, evidence, finding, alert, note}` (default all).
  - **Query plan:**
    - **`observable`:** if `normalize_item` accepts `q` for a detected type (the M4 `_detect` order, then `ja3` for 32 hex), an exact key match first. Then trigram `value_norm % q` (only when `len(q) ≥ 3`), ordered by similarity, limit 20.
    - **`case`:** `to_tsvector('simple', title || ' ' || description) @@ websearch_to_tsquery('simple', q)`, plus an exact or trigram case-number match.
    - **`evidence`:** filename trigram (`len ≥ 3`).
    - **`finding`:** FTS over the title and description of findings in the org.
    - **`alert`:** FTS over `signature`.
    - **`note`:** FTS over the current version of non-deleted notes.

    The expressions must match the phase-1 index expressions exactly (a test runs `EXPLAIN` and asserts index use on the seeded volume).
  - **Execution:** one transaction with `SET LOCAL statement_timeout = SEARCH_STATEMENT_TIMEOUT_MS` (3 000), per-type queries run sequentially, ≤ 20 hits per type. A type that times out is returned as `{type, error: "timeout"}`, and the others still answer.
  - **Hits:** `{type, id, title (bounded, plain), snippet (≤ 200, ts_headline with plain markers converted to ranges, never HTML), case {id, number, tlp}, link descriptor, ts}`. **The query is never logged or audited** (decision). It is in the body only, so no log filter is needed (RT13); the service never logs the body, and errors never echo `q`.
- **Performance:** `test_search_perf.py` seeds about 200 k correlation keys, 50 k findings and alerts, and 5 k cases across two orgs. It asserts p95 < 1 s per type and < 3 s overall on the lane DB, and records the numbers for TESTING.md. It is a heavy-lite step: the parent runs it alone when the seed exceeds that.

## Implementation Steps
1. `normalize.py` and `test_correlation_normalize.py` (key equality with M4 `ti_results` and M6 collection items, IPv4 / IPv6 / mixed-case JA3, private IPs kept, `registry_key` and invalid input ignored).
2. The indexer and `test_correlation_indexer.py`:
   - two orgs and two cases with `seed_correlated_jobs`;
   - idempotence;
   - the cap;
   - a failed job is not indexed;
   - the beat task path through `workers/tasks.py` (phase 1 registration).
3. The job pivot and key lookup; `test_correlation_reads.py` (cross-case hits, never cross-org, common flag, deep links, TI count, invalid value 422).
4. Related cases; `test_correlation_related.py` (ranking, common keys excluded, archived labelled).
5. Search; `test_search.py`:
   - every type finds its seeded row and none of another org's;
   - TLP is shown;
   - deleted notes are absent;
   - FTS parsing of hostile `q` (quotes, `&|!`, Unicode, 256 characters) never 500s;
   - a timeout per type is isolated;
   - the rate limit answers 429;
   - the query text is absent from the logs, including on a 422 and a timeout (caplog);
   - `GET /search` answers 405.
6. `test_search_perf.py` and the EXPLAIN assertions.
7. `idor_cases_correlation.py` with an empty `PENDING_ROUTES`, and `backfill_correlation.py`.

## Success Criteria
- [x] Keys equal the M4 `ioc_key` for IOC kinds, so the TI history and collections join without new code. — `unit/test_correlation_normalize.py::test_ti_eligible_values_equal_the_m4_ti_result_key`, `test_private_values_are_kept_with_the_collection_key`, `test_ja3_keeps_its_case_and_uses_the_opaque_key`; `test_correlation_reads.py::test_keys_join_the_m6_collection_items`, `test_the_lookup_counts_ti_answers_and_lists_collections_of_the_org_only` (9316433).
- [x] Every succeeded job is indexed within one beat interval, idempotently, with a per-job cap. — `test_correlation_indexer.py::test_every_succeeded_job_is_indexed_with_m6_keys`, `test_indexing_is_idempotent_and_restart_safe`, `test_the_per_job_cap_keeps_hashes_and_ja3_first`, `test_failed_and_running_jobs_are_not_indexed`, `test_a_tick_is_bounded_by_the_limit_and_the_budget`, `test_the_beat_task_runs_the_indexer_with_the_batch_setting` (beat every 60 s, ≤ 5 jobs per tick) (9316433).
- [x] "Also seen in", key lookup and related cases work across cases inside one org, never across orgs, with common keys flagged and excluded from the ranking. — `test_correlation_reads.py::test_the_job_pivot_lists_other_cases_of_the_org_only`, `test_the_pivot_of_another_orgs_job_is_404`, `test_common_keys_are_flagged`, `test_the_lookup_normalizes_and_lists_occurrences`; `test_correlation_indexer.py::test_keys_stay_inside_their_org`; `test_correlation_related.py::test_cases_are_ranked_by_shared_keys`, `test_common_keys_are_excluded_from_the_ranking`, `test_archived_cases_are_included_and_labelled`; `idor_cases_correlation.py` (`PENDING_ROUTES` empty) (9316433).
- [ ] Search answers each type within its timeout, uses the phase-1 indexes, never logs the query, and is IDOR-clean. — Met except index use: `test_search.py::test_every_type_finds_its_row_and_never_another_orgs`, `test_a_timeout_is_isolated_per_type_and_nothing_logs_the_query`, `test_an_invalid_query_is_422_without_echo`, `test_hostile_queries_never_fail`, `test_get_is_405_and_csrf_applies`, `test_the_rate_limit_answers_429`, `test_the_query_fragments_match_the_phase_1_index_expressions` (9316433). **Not met:** under RLS the trigram and FTS indexes are not used (`test_the_queries_use_the_phase_1_indexes_under_rls` is a strict xfail), so search is a per-org scan. Accepted pending the perf numbers (notes).
- [ ] The perf numbers are recorded (p95 per type) and support the OpenSearch decision. — **Pending gate:** `test_search_perf.py::test_search_p95_on_the_seeded_volume` exists (about 200 k keys, 50 k findings and alerts, 5 k cases; asserts p95 < 1 s per type and < 3 s overall), but phase 11 runs it alone and no numbers are recorded yet. The OpenSearch decision (deferred, with revisit criteria) is in ARCHITECTURE.

## Risk Assessment
- **Normalizer drift:** correlation follows `normalize_item`; a later change there changes keys for new jobs only. The equality tests against `ti_results` and collection items are the guard.
- **Trigram on short strings:** the minimum length and limits; `pg_trgm.similarity_threshold` set per transaction.
- **Index expression drift** between the migration and the queries silently drops to sequential scans. The EXPLAIN test is the guard.

## Implementation Notes (2026-11-07)
- **Commit:** 9316433 (phases 2–10 together). The schemas, indexes and stubs come from 980386a.
- **Lane 4:** `scripts/lane-test.sh 4 …` on its own files, plus ruff, format and mypy. `test_search_perf.py` was **not** run in the lane: it is a heavy-lite step, and phase 11 runs it alone.
- **`normalize.py`:**
  - `correlation_key` delegates to M6 `normalize_item` with no extra rule (RT8);
  - JA3 keeps its case and uses `opaque_key`;
  - private values are kept with the collection key;
  - `registry_key`, `file_path` and invalid values give `None`;
  - `candidate_keys` detects the type for search and lookup, then adds the pcap-only types.
- **Indexer** (`indexer.py` +272, beat `correlation.index_pending` every 60 s on ingest):
  - it reads the system `analysis_job_index`, then works per org inside `tenant_session`;
  - its sources are `iocs` (every type), `malware_samples` (md5, sha1, sha256) and `evidence_hashes`;
  - inserts use `ON CONFLICT DO NOTHING`, and the `correlation_job_state` row is written in the same transaction;
  - the cap is 20 000 keys, hashes and JA3 first, recorded as `truncated`;
  - a tick is bounded by the 5-job limit and the 10 s budget (RT19).

  `app/scripts/backfill_correlation.py` loops it as a one-off `compose run`.
- **Correlation lookup moved to POST** (security review):
  - `GET /correlations?kind=&value=` became `POST /orgs/{org}/correlations/lookup {kind, value}`, so an IOC value never travels in a URL or an access log (RT13). The GET routes carry ids and filters only.
  - Tests: `test_correlation_reads.py::test_the_lookup_is_a_post_and_the_value_never_travels_in_a_url`, `test_the_lookup_value_is_absent_from_the_logs`, and `test_a_value_that_does_not_normalize_is_422_without_echo`.
- **Contract gap fields** (9316433):
  - the job pivot carries the `source_ids` of this job's IOC rows (the UI joins by id, RT8);
  - the lookup carries the TI answer count (`ti_results`) and the collections (`collections`, `collections_total`);
  - related cases carry `sample_keys` (≤ 5);
  - search carries the TLP, `snippet_ranges` and the per-type `error`.
- **Search** (`search/service.py` +439, `queries.py` +173; `POST /search`):
  - `q` is 2–256 characters with no control characters (`422 search_query_invalid`, never echoed);
  - 30 requests per minute per user;
  - one tenant transaction with `SET LOCAL statement_timeout` (3 s), and each type in its own SAVEPOINT, so a type that times out answers `error: "timeout"` and `partial`;
  - ≤ 20 hits per type, with cursors;
  - plain-text titles and snippets, with UTF-16 `snippet_ranges`;
  - **the query is never logged or audited**: a DB error is logged by type and SQLSTATE only.
- **Search under RLS does not use the trigram / FTS indexes:**
  - `@@`, `%` and `ILIKE` are not `LEAKPROOF`, so the planner cannot push them below the `tenant_isolation` qual.
  - The query fragments equal the 0014 expressions (`test_the_query_fragments_match_the_phase_1_index_expressions`), but `test_the_queries_use_the_phase_1_indexes_under_rls` is a **strict xfail**.
  - Search is a per-org scan over the `organization_id` btree. The exact observable match uses `(organization_id, kind, key)`.
  - This is accepted for M7 pending the perf numbers. The fix (LEAKPROOF wrappers or a `SECURITY DEFINER` search function) is a migration-0015 decision. Recorded in ARCHITECTURE, DATABASE, THREAT_MODEL and ROADMAP.
- **Tests** (9316433):
  - `unit/test_correlation_normalize.py`: 6;
  - `test_correlation_indexer.py`: 8;
  - `test_correlation_reads.py`: 15;
  - `test_correlation_related.py`: 6;
  - `test_search.py`: 12, one of them the strict xfail;
  - `test_search_perf.py`: 1 (heavy-lite);
  - `idor_cases_correlation.py`, with `PENDING_ROUTES` empty.
- **Purged jobs keep their keys** (RT9): `test_keys_survive_a_purge_of_the_job_results`.
- **Pending gate:** the search p95 per type (`test_search_perf.py`, run alone), the TESTING.md perf table, and with them the decision whether the per-org scan holds.
