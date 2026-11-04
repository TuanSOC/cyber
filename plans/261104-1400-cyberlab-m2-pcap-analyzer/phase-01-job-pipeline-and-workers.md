---
phase: 1
title: Job pipeline and workers
status: completed
priority: P1
effort: 16h
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

## Implementation Notes (2026-11-04)
- **Layout:** image workdirs moved to `/srv/api` and `/srv/workers/pcap` (was `/app`). uv cannot resolve the relative path dependency `../../packages/py-jobs` above `/`; at this depth the path in the image matches the repo. Compose `additional_contexts: jobs` puts the package at `/packages/py-jobs`.
- **Sandbox (after the Critical review finding):**
  - Process discovery reads the `Uid:` line of `/proc/<pid>/status`, not the `/proc` directory owner, because non-dumpable processes get a root-owned entry.
  - Killing is done by a forked helper that becomes uid 10003 and calls `kill(-1, SIGKILL)`. On Linux that call returns 0 whenever any other process exists, so the result is verified by re-scanning.
  - Fail closed: if a tool process survives, the worker SIGTERMs PID 1 (tini); compose restarts the container (`restart: unless-stopped`).
  - `reset()` runs before every job and on `worker_process_init` (kills tool processes, wipes `/work`).
  - Tools get seccomp (libseccomp via ctypes): `socket()` with AF_INET, AF_INET6 or AF_PACKET returns EACCES.
  - Tools get `TMPDIR` set to their own out/ directory; `/tmp` and `/dev/shm` are root-only tmpfs.
  - Root never follows tool-created names: reads use `open_output`, stdout/stderr files are created via `dir_fd` with `O_EXCL | O_NOFOLLOW`, and stdout names are random per run.
- **Broker ACL:**
  - The `pcap` user uses key selectors:
    - read/write its own `pcap*` keys and pcap bindings;
    - write-only on `ingest*`;
    - read-only on ingest bindings (both `_kombu.binding.*` and kombu's newer `_kombu.binding_permanent.*`).
  - Each app has its own unacked keys: `pcap.unacked*` for the analyzer, `trusted.unacked*` for the trusted side.
  - The analyzer publishes ingest reports through a `no_declare` queue; the trusted side declares the bindings.
  - `maxmemory 256mb noeviction`.
  - `LLEN` on the ingest queue stays possible: Redis treats it as metadata.
- **DB (migration 0003):**
  - `analysis_job_index` has forced RLS: system sessions (no org) see all rows, tenant sessions only their own org's.
  - The app role may UPDATE only `status` and `deadline_at`.
  - The trigger enforces the transition graph (queued→running|succeeded|failed, running→succeeded|failed); final states never change.
- **Dispatch:**
  - Dedicated `broker_limiter` (4 threads).
  - Publish timeout 15 s with `abandon_on_cancel`, broker socket timeouts, a single retry.
  - Nothing after commit can make the request fail (enqueue failure → `enqueue_failed`; failure to record that is logged and left to the reaper).
- **Fairness:**
  - Global active-job cap of 50, on top of the per-org cap of 5.
  - Auto-runs limited to 30 per 10 min per user (skipped and audited with `rate_limited`).
  - Fair per-org dequeue is deferred (single FIFO, concurrency 1).
- **Ingest:**
  - Authenticates without row locks and stats the result object before locking.
  - Retries only transient errors (DB/connection/urllib3); permanent errors fail the job with `ingest_error`.
  - The reaper re-checks status and deadline under the lock.
- **Tests:**
  - API: 375 tests (analysis rules, ingest auth/transitions/retry classes, reaper races, RLS/grants/trigger, IDOR for 4 new routes with positive controls, real-worker pipeline: success, hash mismatch, size mismatch, compressed capture).
  - Worker: 24 in-container tests (uid, caps, environ, capture read-only, symlink/fifo/planted names, timeout, setsid and non-dumpable survivors, reset between jobs, seccomp, TMPDIR, no DNS for app services, no egress, ACL key confinement).
- **Accepted residuals (THREAT_MODEL in phase 6):**
  - A compromised Celery root process (not just a tool) could LPUSH forged or extra reports or DEL the ingest list. Forged reports for other jobs still need that job's token.
  - Tools share the network namespace (seccomp blocks inet sockets, not unix sockets).
  - MinIO is reachable from the analysis network.
  - Messages under an ETA retry are restored after the 1 h visibility timeout if the ingest worker restarts.

## Risk Assessment
- Container root with a few capabilities: acceptable because tools never run as root. no-new-privileges and a read-only rootfs limit what the root process could be abused for.
- kombu commands needed under the ACL must be discovered by testing. Start from the list of kombu Redis transport commands and tighten.
