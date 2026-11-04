---
phase: 1
title: "Job pipeline and workers"
status: pending
priority: P1
effort: "16h"
dependencies: []
---

# Phase 1: Job pipeline and workers

## Overview
End-to-end job plumbing with a no-op analyzer:
1. The API creates a job.
2. The broker delivers it to the isolated pcap-worker.
3. The worker fetches the evidence by presigned URL and verifies its hash.
4. It runs a stub "tool" as the unprivileged tool uid and uploads a minimal result by presigned POST.
5. The trusted ingest-worker marks the job succeeded or failed.

## Requirements
- Functional:
  - `analysis_jobs` table (tenant) + `analysis_job_index` (non-tenant: job_id, organization_id, status, deadline_at) [RT4].
  - Routes:
    - `POST /orgs/{org}/evidence/{id}/analyses` `{analyzer:"pcap"}` (evidence.write).
    - `GET /orgs/{org}/evidence/{id}/analyses` (evidence.read).
    - `GET /orgs/{org}/analyses/{job_id}` (evidence.read).
    - `GET /orgs/{org}/analyses?status` (evidence.read).
  - Auto-enqueue on upload when the head has a pcap/pcapng magic number [RT12].
  - Re-run creates a new job (history kept).
- Refusals:
  - 409 `analysis_active`: one active job per (evidence, analyzer), via partial unique index.
  - 429 `analysis_queue_full`: more than 5 active jobs per org [RT7].
  - 413 `capture_too_large`: size > `PCAP_MAX_BYTES` [RT5].
  - 409: archived evidence or investigation.
- Non-functional:
  - Enqueue runs after commit and is best effort. Failure → job `failed` with `enqueue_failed`.
  - Upload never fails because of analysis [RT12].

## Architecture
- `packages/py-jobs` (`cyberlab_jobs`, pydantic v2 only, `extra="forbid"` everywhere):
  - `PcapJobV1 {schema_version:"pcap.v1", job_id, organization_id, evidence_id, expected_sha256, size_bytes, evidence_url, result_post {url, fields}, ingest_token, limits}`.
  - `IngestMessageV1 {job_id, organization_id, ingest_token, event: started|finished, outcome?, error_code?, result_version_id?, worker_version}`.
  - `JobLimits {max_bytes, timeout_s, tool_timeout_s, max_flows, max_records_per_kind, max_findings, max_result_bytes}`.
  - Task-name constants. Result line models come in phase 2.
- Celery:
  - JSON only.
  - `pcap.analyze` acks early (default ack), `expires` = 6 h, soft limit = timeout + 60 s, hard limit = soft + 30 s [RT3].
  - Worker flags: `--concurrency 1 --max-tasks-per-child 1 --without-gossip --without-mingle --without-heartbeat`, `worker_enable_remote_control=False`.
  - The ingest queue uses acks_late (idempotent handler).
- Privilege separation in pcap-worker [RT1]:
  - The container runs as root with `cap_drop: ALL` + `cap_add: [SETUID, SETGID, KILL, CHOWN, DAC_OVERRIDE, FOWNER]`, `no-new-privileges`, `read_only`, `pids_limit 256`, `mem_limit 2g`.
  - The Celery process owns the broker URL and the job message.
  - Every tool runs via `subprocess(user=10003, group=10003, extra_groups=[], start_new_session=True, env=minimal, cwd=job dir, umask 077)`.
  - After the job: `os.killpg` + kill every uid-10003 process (scan `/proc`), then `rm -rf` the job dir.
  - Spool dir on the `pcap_work` volume: root-owned 0711; the job dir is owned by 10003. The input file is root-owned 0444.
- Ingest-worker (api image, app role, scoped MinIO, broker):
  - Validates the message, finds the job via `analysis_job_index` and compares `sha256(ingest_token)`.
  - Opens `tenant_session(index.organization_id)` and applies guarded transitions (`queued→running`, `running→succeeded|failed`) [RT3/RT4].
  - Beat (schedule file on tmpfs) runs the reaper every 60 s: queued past deadline → `never_started`, running past deadline → `timed_out`.
- Broker [RT1/RT2]:
  - `redis-broker` with ACL file. Users: `api` (enqueue), `ingest`, `pcap` (pcap-queue commands only, `-@dangerous -keys -scan -monitor -client -config`). Default user off.
  - Networks: `analysis` (`internal: true`) + `backend`.
- MinIO:
  - New bucket `analysis-results` (versioned).
  - api policy +Get/PutObject on it.
  - Presigned GET of the exact evidence version, and a presigned POST policy with `content-length-range` 0..`max_result_bytes`, key = `results/{org}/{job}.ndjson.gz`.
  - Both are signed for host `minio:9000`.
- Custody: `analysis_requested` (actor = requester).

## Related Code Files
- Create:
  - `packages/py-jobs/**`
  - `apps/api/app/modules/analysis/{models,schemas,repository,service,router,dispatch}.py`
  - `apps/api/app/workers/{celery_app,ingest,reaper}.py`
  - `apps/workers/pcap/{Dockerfile,pyproject.toml,uv.lock,pcap_worker/{celery_app,tasks,fetch,sandbox,upload}.py,tests/}`
  - `infra/redis-broker/users.acl.template` + init
  - `apps/api/alembic/versions/0002_analysis_jobs.py`
- Modify:
  - `apps/api/{Dockerfile,pyproject.toml}`
  - `docker-compose*.yml`, `.env.example`
  - `infra/minio/{init.sh,api-policy.template.json}`
  - evidence upload (auto-enqueue), custody enum
  - IDOR route cases, `test_tenant_session_guard.py` allowlist, config.

## Implementation Steps
1. py-jobs package and unit tests.
2. Path dependency (uv source, editable) and BuildKit `additional_contexts`.
3. Migration 0002 + models; RLS/grants; index table grants (SELECT, INSERT, UPDATE).
4. API module, routes, magic detection, auto-enqueue, rate limit (manual 20/10 min).
5. Broker service + ACL + compose networks.
6. pcap-worker:
   - fetch: size cap + sha256 streaming; mismatch → `integrity_mismatch`.
   - sandbox runner: stub tool = `sha256sum` run as 10003.
   - presigned POST upload; started/finished ingest messages.
7. Ingest-worker and reaper.
8. Tests:
   - API integration (routes, refusals, RBAC, auto-enqueue on magic only, enqueue failure).
   - Ingest unit tests (token mismatch, unknown job, illegal transition, late message after reaper).
   - Container tests:
     - Real job reaches `succeeded`; a tampered object gives `integrity_mismatch`.
     - The tool uid cannot read `/proc/1/environ`, and its leftover processes are killed.
     - Worker ACL refuses MONITOR/KEYS.
     - Egress blocked; `postgres` / `redis` unresolvable from pcap-worker.

## Success Criteria
- [ ] A pcap upload creates a job that reaches `succeeded` with the stub analyzer.
- [ ] pcap-worker env has only the broker URL (ACL user); tools cannot read it.
- [ ] Hash mismatch → failed `integrity_mismatch`; reaper and late messages never reopen a terminal job.
- [ ] Every new org route has IDOR cases with a positive control.

## Risk Assessment
- Container root with a few capabilities: acceptable because tools never run as root. no-new-privileges and a read-only rootfs limit what the root process could be abused for.
- kombu commands needed under the ACL must be discovered by testing. Start from the list of kombu Redis transport commands and tighten.
