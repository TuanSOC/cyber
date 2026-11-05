---
phase: 5
title: "Runtime job metrics and live run procedures"
status: pending
priority: P1
effort: "10h"
dependencies: [1]
---

# Phase 5: Runtime job metrics and live run procedures (group B, 2d, lane 5; the replay is a heavy step)

## Overview
The §14 runtime metrics over real runs, plus the procedure for the unmeasured live TI and AI behaviour:
- `job_outcomes` is filled by the phase-1 triggers;
- this phase verifies the triggers, aggregates the outcomes, serves them as Prometheus text on an internal endpoint and as an org page API, replays the M2 / M3 datasets through the real workers, and adds the guarded live-run wrapper.

The design is in plan.md "Runtime metrics".

**Owns:**
- `app/modules/ops/{metrics,router,internal}.py` (`error_classes.py` stays frozen from phase 1);
- `scripts/ops_metrics.py` and `scripts/live_run.mjs` (after the stubs);
- `tests/security/idor_cases_ops.py`;
- `tests/integration/test_job_outcomes_triggers.py`, `test_ops_metrics.py` and `test_internal_metrics.py`;
- `tests/unit/test_prometheus_render.py`.

## Requirements
- **Trigger verification** (`test_job_outcomes_triggers.py`, lane DB):
  - every terminal transition writes exactly one `job_outcomes` row, through the normal lifecycle paths and through the reaper fail paths: pcap and static `succeeded` / `failed` / timeout reaped, TI `succeeded` / `failed` / `expired`, AI `completed` / `failed` / `policy_blocked`, renders `succeeded` / `failed`, `purged` excluded;
  - no row for non-terminal changes;
  - the row has no org id or tenant text;
  - the app role cannot INSERT, UPDATE or DELETE `job_outcomes`;
  - the trigger never blocks a status change (a NULL `started_at` gives a NULL `queue_ms` / `run_ms`, never an error);
  - a bulk reaper fail of 500 jobs adds < 20 % to its duration (measured and recorded).
- **Aggregation** (`metrics.py: platform_metrics(session, now)`):
  - windows 1 h, 24 h and 7 d;
  - per (`kind`, `subkind`): counts by status, the failure ratio (failed over terminal), duration quantiles with `percentile_cont` (p50, p95, p99) for `run_ms` and `queue_ms`, and the parse success ratio (succeeded / (succeeded + failed with `classify(code) == parse`));
  - failure counts by error class;
  - active gauges from the `*_index` tables (`queued` / `running` counts per analyzer, TI, AI and render).

  One SQL statement per window, under `SET LOCAL statement_timeout = '2s'`.
- **`render_prometheus`:** text exposition 0.0.4.
  - Metric names `cyberlab_jobs`, `cyberlab_job_failure_ratio`, `cyberlab_parse_success_ratio`, `cyberlab_job_duration_seconds` (summary-style quantile labels), `cyberlab_jobs_active` and `cyberlab_job_failures_by_class`.
  - Labels `kind`, `subkind`, `status`, `window`, `class`, from fixed enums only. Error codes are never labels: they are classified first.
  - HELP and TYPE lines; label values escaped. The unit test checks the format with a strict parser (the `prometheus_client` text parser as a dev dependency **only if** it is already in the lock; otherwise a small regex validator).
- **`GET /internal/metrics`** (`internal.py`, on the root app):
  - 404 when `METRICS_TOKEN_FILE` is unset;
  - 401 without `Authorization: Bearer <token>` (constant-time compare);
  - 403 when `X-Forwarded-For` or `Forwarded` is present: defence in depth only, since uvicorn trusts that header from any peer and a backend caller can omit it; the bearer token is the control (RT27);
  - `Cache-Control: no-store`; a rate limit of 60 / min per peer.
  - `test_internal_metrics.py` also asserts that the gateway config does not route `/internal/*` (the Caddy file test pattern from M3).
- **`GET /orgs/{org}/ops/metrics?window=24h|7d`** (`audit.read`): the same numbers from the **tenant** tables of the org (`analysis_jobs`, `ti_enrichment_runs`, `ai_runs`, `report_renders`), not from `job_outcomes`, which has no org. Plus the five most recent failures (job id, analyzer, error code and class, finished_at, deep link). `test_ops_metrics.py`: the numbers equal a hand count on the seed; another org's jobs are absent; viewer 403.
- **`scripts/ops_metrics.py`** (a heavy step; it runs on the host with the full dev stack and the analyzers up, alone):
  1. Register a throwaway org (or use `--org`).
  2. Upload the M2 dataset pcaps (`apps/workers/pcap/dataset/`, generated if absent, as the M2 metric harness does) and the M3 sample set.
  3. Wait for the jobs, `--rounds 3` by default.
  4. Read `GET /ops/metrics` and `/internal/metrics`.
  5. Write `plans/reports/ops-metric-YYMMDD.md`: rounds, jobs per analyzer, failure rate, run and queue latency p50 / p95, parse success, failures by class, host notes (RAM, image tags), and the command line.

  It never runs in the gate (phase 11 records the gate's own e2e jobs separately).
- **`scripts/live_run.mjs`** (never in the gate):
  - **Refuses unless** `CYBERLAB_LIVE=1`, `.secrets/live.env` exists (provider keys; gitignored through `.secrets/`), and `--max-calls` (default 20) and `--max-usd` (default 2) are given.
  - **Runs**, inside `api-test` with the live env file passed through `--env-file`:
    - `tests/unit/test_ai_provider_live.py` and `tests/ai_eval/test_ai_eval_live.py` with `AI_LIVE_MAX_CALLS`;
    - `tests/unit/test_ti_provider_live.py` per configured provider.
  - **Output:** `plans/reports/live-run-YYMMDD.md` from a template: providers, model ids, calls, cost estimate, citation accuracy, enrichment success, failures. **No keys or raw provider responses** in the report.
  - **Network:** `api-test` has no route out (`backend` is internal), and `lane-test.sh --service` accepts only `api-test` and `report-worker-test`. Step 6 first reads how the existing live tests reach the provider; if they need egress, the wrapper runs them in a one-off `compose run --rm` of `analyst-worker-test` / `enrich-worker-test` (they are on `egress`) with `--env-file .secrets/live.env`, never adding egress to `api-test`. The choice is recorded in the phase notes.
  - Without keys, the report is written with `status: not run`.

## Implementation Steps
1. The trigger tests (they may expose a phase-1 bug → a parent change request).
2. `metrics.py` and `render_prometheus` with the unit test.
3. The internal endpoint and its tests.
4. The org metrics route and `idor_cases_ops.py` (empty `PENDING_ROUTES`).
5. `ops_metrics.py`. The parent runs it once alone (heavy) after the lanes, and the report is committed.
6. `live_run.mjs` and its template. Run it only if the user supplies keys; otherwise commit the "not run" report.

## Success Criteria
- [ ] Every terminal job, run and render, including the reaper paths, produces exactly one tenant-free `job_outcomes` row, and the trigger never blocks a transition.
- [ ] `/internal/metrics` serves valid Prometheus text with fixed labels only to a bearer on the backend network, and is unreachable through the gateway.
- [ ] The org metrics route reports the org's own failure rate, latency and parse success, IDOR-clean.
- [ ] `plans/reports/ops-metric-YYMMDD.md` records the replay over real workers.
- [ ] The live-run wrapper is guarded and documented, and its report says run or "not run".

## Risk Assessment
- **Percentiles on large windows:** the 7 d window over `job_outcomes` uses the `(kind, finished_at)` index. At this scale it is fine; measured in step 2.
- **Live tests' container:** the existing live tests may assume egress. Resolve it before writing the wrapper, and never add egress to `api-test`.
- **Replay memory:** pcap-worker plus static-worker plus the stack is about 6 GB. Run the pcap round and the static round sequentially, stopping the other analyzer.
