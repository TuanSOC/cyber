---
phase: 4
title: "Ingest persistence and read API"
status: pending
priority: P1
effort: "12h"
dependencies: [3]
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

## Risk Assessment
- Large inserts holding a transaction → batches inside one txn are OK at M2 scale; statement
  timeout raised for the ingest role session only (`SET LOCAL statement_timeout`).
