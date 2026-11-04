---
phase: 4
title: Ingest persistence and read API
status: completed
priority: P1
effort: 12h
dependencies:
  - 3
---

# Phase 4: Ingest persistence and read API

## Overview
Trusted ingest streams the result, validates every line, persists it into tenant tables, and
the API exposes paginated, filterable read endpoints.

## Requirements
- Tables (all tenant, RLS ENABLE+FORCE, composite FKs to `analysis_jobs(id, organization_id)`,
  SELECT/INSERT only for the app role, delete only via job cascade by owner — never by app):
  - `network_flows` (ts, duration, src/dst ip `inet` + port, proto, service, bytes/packets
    each direction, conn_state, flow_ref, community_id)
  - `network_records` (kind dns|http|tls, ts, src/dst, flow_ref, `summary` text, `details` jsonb)
  - `network_alerts` (ts, sid, rev, signature, category, severity, src/dst, flow_ref, community_id)
  - `analysis_findings` (type, title, description, severity, confidence, detection_method,
    ts, src/dst, protocol, evidence_refs jsonb)
  - `iocs` (type, value, first/last seen, count, source; unique (job, type, value))
  - `analysis_jobs.summary` jsonb (capture meta, protocol hierarchy, top talkers, counts,
    tool versions, engine_errors, truncation flags)
- Ingest [RT11]: download the exact result version (id recorded on the job [RT6]) to a temp
  file with a decompressed-size cap; validate every line (unknown kinds/fields rejected, string
  length caps, `details` depth/size caps, ts within capture window ± 1 day) and the trailer
  (count + sha256) **before** opening a transaction; then one transaction, `SET LOCAL
  statement_timeout`, asyncpg `copy_records_to_table` per table. All-or-nothing: any error →
  zero rows, job failed `invalid_result`.
- Read API (evidence.read), all `Page[T]`:
  - `GET /orgs/{org}/analyses/{job}/findings?severity&type`
  - `.../flows?ip&port&proto&sort` (sort bytes|ts), `.../records?kind&q`, `.../alerts?severity`,
    `.../iocs?type&q`, `.../timeline`, summary inside `GET /orgs/{org}/analyses/{job}`
- Custody: `analyzed` event (job id, tool versions) on success.

## Architecture
- `apps/api/app/modules/pcap_analysis/{models,schemas,repository,ingest,router}.py`;
  ingest uses streaming gzip reader with a hard decompressed-size cap (zip-bomb guard).
- btree indexes on (job, ts), (job, src_ip), (job, dst_ip), (job, kind); text filters use
  `ILIKE` with escaped patterns bounded to one job (no `pg_trgm`, YAGNI) [RT13].

## Success Criteria
- [ ] Hostile result fixtures (unknown kind, oversized string, bad trailer, bomb gzip,
      foreign org id in lines) → job failed, zero rows.
- [ ] IDOR tests cover all new routes; RLS coverage test passes for new tables.
- [ ] Ingest of `mixed` scenario < 5 s; 100k-flow synthetic result < 60 s.

## Implementation Notes (2026-11-04)
- Built by a subagent; reviewed by a second subagent (0 Critical/High, 6 Medium/Low + test gaps); all fixed by a third subagent. Contract fixes (finite and bigint-bounded attributes, NUL-free header text, bounded `detection_method`, refusal of out-of-int64 ints) done by the parent in `packages/py-jobs`.
- **Tables** (0004): `network_flows` (`total_bytes` clamped and indexed), `network_records`, `network_alerts`, `analysis_findings` (finding id unique per job), `iocs` (unique on job, type, md5(value)), `analysis_timeline`. All have a composite FK to `analysis_jobs` with cascade, forced RLS, and SELECT/INSERT grants only. Migration 0005 adds port and IOC-ordering indexes.
- **Ingest:**
  1. Skip if the job is already final.
  2. Stream the exact result version to a disk scratch dir (`INGEST_TMP_DIR`, free space checked first; ENOSPC is transient).
  3. Validate in a thread:
     - inflated-size cap, line caps (1 MiB per line, 400 k total);
     - header names this job, middle lines pass the contract, exactly one stats line, per-kind caps;
     - no duplicate finding ids or IOCs (md5, same as the index);
     - trailer count and sha256 match;
     - timestamps inside the capture window ± 1 day.
  4. One transaction: transaction-local statement and idle timeouts, job row locked and status re-checked, batched INSERTs (1 000 lines or 8 MiB; COPY is impossible with RLS), rows written must equal rows validated, then summary + succeeded + custody `analyzed` + audit.
  5. Any validation failure, or a database refusing a value (SQLSTATE 22/23, asyncpg client-side errors), fails the job as `invalid_result` with zero rows.
  - Scratch leftovers are swept at worker start; the worker refuses to start without a scratch dir outside tests.
- **Read API:** six `GET /orgs/{org}/analyses/{job}/…` routes, `evidence.read`, 404 for foreign jobs, `Ip` type for IP filters (no zone ids), escaped ILIKE, sort whitelist. Totals are capped at 10 001 (`CappedPage`); keyset pagination is deferred.
- **Measured:** 100 k flows ingest in ≈ 20 s.
- **Tests:** 586 API tests (hostile streams, DB-error rollback, reaper race, tmp cleanup, timeouts reset, cross-org row counts, contract-vs-column parity, IDOR cases for every new route).
- **Compose:** reaper beat moved to its own `ingest-beat` service (a long ingest can no longer delay it); ingest-worker scratch on the `ingest_tmp` volume.

## Risk Assessment
- Large inserts holding a transaction → batches inside one txn are OK at M2 scale; statement
  timeout raised for the ingest role session only (`SET LOCAL statement_timeout`).
