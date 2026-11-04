---
title: CyberLab M2 PCAP Analyzer
description: >-
  First analysis engine: isolated PCAP worker (TShark, Zeek, Suricata) behind a
  versioned job schema, trusted ingest into tenant tables, detections
  (beaconing, scans, DNS anomalies, suspicious traffic), IOCs, timeline,
  analyzer UI.
status: completed
priority: P1
effort: 70h
branch: feat/m2-pcap-analyzer
tags:
  - feature
  - analysis
blockedBy:
  - 261104-1000-cyberlab-m1-foundation
blocks: []
created: '2026-11-04T06:17:05.692Z'
createdBy: 'ck:plan'
source: skill
---

# CyberLab M2 PCAP Analyzer

## Overview

`requirement.txt` §5 (PCAP engine), §4 (separate workers, versioned job schemas, API never
executes untrusted files), §11 (analysis_jobs, network_flows, network_alerts, iocs,
timeline), §14 (anonymized controlled dataset, parsing success rate, latency,
precision/recall). Builds on M1 (commit 5f3d5b7).

## Architecture (decided)

```
upload (pcap/pcapng) ──► API ──creates──► analysis_jobs row (queued) ──enqueue──► broker (redis-broker)
                                                                                      │
        ┌─────────────────────────── queue "pcap" ◄────────────────────────────────────┘
        ▼
  pcap-worker  (UNTRUSTED: parses attacker-controlled bytes)
    - no DB creds, no MinIO creds: presigned GET (evidence version) + presigned PUT (result)
    - verifies sha256 of downloaded bytes == job.expected_sha256 before parsing
    - capinfos/tshark + zeek + suricata under prlimit, non-root, cap_drop ALL, ro rootfs, tmpfs
    - detections in Python over normalized records
    - uploads result.ndjson.gz, then enqueues "ingest" task {job_id, status}
        │
        ▼ queue "ingest"
  ingest-worker (TRUSTED: api image, app DB role, scoped MinIO user)
    - re-derives result key from job_id (never trusts a key from the message)
    - streams + validates every line against cyberlab_jobs pydantic models, caps counts
    - writes findings / flows / records / alerts / iocs in tenant_session(job.org_id)
    - audit + custody event "analyzed"; reaper marks stale jobs failed
```

## Key decisions (defaults chosen autonomously; reversible)

- **Two-stage worker split** (untrusted parser vs trusted ingest): a parser compromise
  cannot read or write the database or other tenants' objects except via URLs in broker
  messages (documented gap; Redis ACLs later).
- **Separate `redis-broker` instance**: the parser never reaches the app Redis (token
  denylist, rate limits).
- **Celery** (requirement) with JSON serializer only, `task_acks_late`, `worker_prefetch_multiplier=1`,
  no result backend (results travel via MinIO + ingest task).
- **Shared versioned contract package** `packages/py-jobs` (`cyberlab_jobs`): job message
  `PcapJobV1`, result header + record models, `schema_version="pcap.v1"`; path dependency of
  both api and worker (BuildKit `additional_contexts`).
- **One worker image** on `zeek/zeek:8.0` (Debian 13): Zeek 8.0.10 + apt `tshark` 4.4 +
  `suricata` 7.0 + `suricata-update` (ET Open fetched at build; rule version recorded in result).
- **Zeek is the primary flow/DNS/HTTP/TLS source**; TShark gives capture metadata, format
  validation and protocol hierarchy; Suricata gives signature alerts. No duplicate parsing.
- **OpenSearch deferred** (YAGNI at this scale; heavy on Docker Desktop): Postgres indexes +
  `pg_trgm` for search. Revisit when result volume needs it.
- **Auto-analysis on upload** when libmagic says pcap/pcapng; manual (re)run for analysts.
  Read permission = `evidence.read`; run = `evidence.write`.
- **Findings never say "malicious"** from heuristics or reputation: type, severity,
  confidence, detection_method, evidence_refs (zeek uid / suricata flow_id / frame numbers).
- **Synthetic, labeled dataset** generated with scapy (deterministic seed, ground-truth JSON);
  no real captures in the repo.

## Red-team changes (2026-11-04, all applied)

- RT1 (Critical, broker reachable from a compromised parser). Fixes:
  - **Privilege separation inside pcap-worker.** The Celery process holds the broker credentials. Tools run as uid 10003 with no capabilities and no readable parent environ/memory.
  - After every job the worker kills every uid-10003 process and wipes the job directory.
  - Redis ACL user for the worker (no MONITOR/KEYS/SCAN/CONFIG/CLIENT/FLUSH*/DEBUG).
  - Per-job ingest token (sha256 stored on the job).
  - `--max-tasks-per-child=1`.
- RT2: `analysis` network `internal: true` (no egress); rules fetched only at build time; egress-blocked test; MinIO exposure to the parser network documented.
- RT3:
  - `pcap.analyze` acks early (never redelivered) and has a Celery `expires`.
  - Ingest uses guarded transitions (`WHERE status IN (...)`); terminal states are final.
  - Tools run with `start_new_session` and the whole process group is killed; tool timeouts are below the task soft limit.
- RT4: system-side job lookups through a non-tenant `analysis_job_index(job_id, organization_id, status, deadline_at)` table, updated in the same transaction. Ingest and the reaper read it, then open `tenant_session(org)` (guard allowlist entry for `app/workers/`). Custody actor for `analyzed` = requester, `details.system=true`.
- RT5:
  - `PCAP_MAX_BYTES` (default 512 MiB), refused at job creation with `capture_too_large`.
  - Disk-backed `pcap_work` volume instead of a large tmpfs.
  - Suricata `--runmode single` + measured memory; no `RLIMIT_AS` until measured (CPU + wall-clock + container memory limits).
- RT6:
  - Result upload by presigned **POST policy** with `content-length-range`.
  - Ingest reads, and records, the exact result version id + sha256.
  - `/export` dropped (YAGNI).
- RT7:
  - URL TTL = Celery `expires` = reaper queued threshold (6 h); `url_expired` code.
  - Max 5 active jobs per org (manual → 429 `analysis_queue_full`; auto-run skipped and audited).
- RT8: exact Suricata flags (`-l <job>/suri -k none`, unix socket off); `HOME=/work/<job>`; Celery beat schedule on tmpfs.
- RT9: JA3/JA3S from Suricata eve `tls`; JA4 out of M2. Dataset certificates generated with `cryptography` over TLS 1.2. `@load policy/protocols/conn/community-id-logging`.
- RT10: tests use their own broker db index and queue prefix; the test ingest runs in-process against the test DB.
- RT11: ingest downloads and fully validates the stream into a temp file first, then writes once in a single transaction via asyncpg `copy_records_to_table`, with `SET LOCAL` timeouts.
- RT12:
  - Captures are detected by magic number (pcap µs/ns, both endians, pcapng `0A0D0D0A`) on the upload head, not libmagic.
  - Enqueue is best effort after commit; closed investigations are refused.
  - THREAT_MODEL libmagic item re-deferred explicitly.
- RT13:
  - Compressed captures (gzip/zstd/lz4) are refused with `unsupported_capture_format`.
  - Worker failure rate measured.
  - Rule snapshot sha256 + version recorded.
  - Nonce CSP re-deferred to M3 (documented).
  - `pg_trgm` and cross-case findings dropped.
  - §11 mapping: `analysis_results` = `analysis_jobs.summary` + findings tables; `investigation_timeline` per job in M2.
  - Effort raised (P2 18 h, P5 14 h).

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [Job pipeline and workers](./phase-01-job-pipeline-and-workers.md) | Completed |
| 2 | [PCAP engine and dataset](./phase-02-pcap-engine-and-dataset.md) | Completed |
| 3 | [Detections and IOCs](./phase-03-detections-and-iocs.md) | Completed |
| 4 | [Ingest persistence and read API](./phase-04-ingest-persistence-and-read-api.md) | Completed |
| 5 | [Frontend PCAP analyzer](./phase-05-frontend-pcap-analyzer.md) | Completed |
| 6 | [Hardening e2e and docs](./phase-06-hardening-e2e-and-docs.md) | Completed |

## Dependencies

- Blocked by M1 foundation (completed).
- Phase order is strict: 1 → 2 → 3 → 4 → 5 → 6 (4 needs the result contract from 2–3).

## Definition of done

- Upload a synthetic PCAP in the browser → job runs automatically → findings, alerts, flows,
  DNS/HTTP/TLS records, IOCs and timeline are visible; re-run works; failure is visible.
- Dataset metrics recorded in TESTING.md: parsing success rate, latency, per-detector
  precision/recall on the labeled dataset.
- Parser isolation verified by tests (no DB/MinIO creds in pcap-worker env, no route to
  app Redis/Postgres, integrity mismatch refused, oversize/timeout handled).
- `pnpm verify` and `pnpm verify:prod` green; IDOR coverage includes every new route.
- docs: PCAP_ANALYSIS.md new; ARCHITECTURE, DATABASE, API, THREAT_MODEL, TESTING,
  DEPLOYMENT, ROADMAP updated.
