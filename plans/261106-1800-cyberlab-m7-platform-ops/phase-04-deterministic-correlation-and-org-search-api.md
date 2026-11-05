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
- [ ] Keys equal the M4 `ioc_key` for IOC kinds, so the TI history and collections join without new code.
- [ ] Every succeeded job is indexed within one beat interval, idempotently, with a per-job cap.
- [ ] "Also seen in", key lookup and related cases work across cases inside one org, never across orgs, with common keys flagged and excluded from the ranking.
- [ ] Search answers each type within its timeout, uses the phase-1 indexes, never logs the query, and is IDOR-clean.
- [ ] The perf numbers are recorded (p95 per type) and support the OpenSearch decision.

## Risk Assessment
- **Normalizer drift:** correlation follows `normalize_item`; a later change there changes keys for new jobs only. The equality tests against `ti_results` and collection items are the guard.
- **Trigram on short strings:** the minimum length and limits; `pg_trgm.similarity_threshold` set per transaction.
- **Index expression drift** between the migration and the queries silently drops to sequential scans. The EXPLAIN test is the guard.
