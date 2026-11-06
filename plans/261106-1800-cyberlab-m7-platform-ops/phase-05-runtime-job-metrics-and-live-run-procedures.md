---
phase: 5
title: "Runtime job metrics and live run procedures"
status: completed
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
- [x] Every terminal job, run and render, including the reaper paths, produces exactly one tenant-free `job_outcomes` row, and the trigger never blocks a transition. — `test_job_outcomes_triggers.py::test_analysis_lifecycle_writes_one_row_per_terminal_transition`, `test_the_analysis_reaper_fail_paths_write_one_row_each`, `test_ti_runs_write_one_row_per_final_status`, `test_ai_runs_write_one_row_per_final_status`, `test_renders_write_one_row_per_final_status_and_none_on_purge`, `test_rows_hold_no_tenant_data`, `test_the_app_role_cannot_write_job_outcomes`, `test_the_trigger_never_blocks_the_transition`, `test_bulk_reaper_fail_cost_of_the_trigger` (+2.8 %, the limit is 20 %) (9316433).
- [x] `/internal/metrics` serves valid Prometheus text with fixed labels only to a bearer on the backend network, and is unreachable through the gateway. — `test_internal_metrics.py::test_off_without_a_token`, `test_the_bearer_token_is_required`, `test_a_proxied_request_is_refused`, `test_rate_limited_in_one_global_window`, `test_serves_valid_prometheus_text_with_fixed_labels`, `test_not_in_the_api_schema_and_outside_api`, `test_the_gateway_never_routes_internal`; `unit/test_prometheus_render.py` (5, a strict regex validator) (9316433).
- [x] The org metrics route reports the org's own failure rate, latency and parse success, IDOR-clean. — `test_ops_metrics.py::test_the_numbers_equal_a_hand_count_and_other_orgs_are_absent`, `test_only_audit_readers_see_the_metrics`, `test_the_five_most_recent_failures_of_the_org_only`; `idor_cases_ops.py` (`PENDING_ROUTES` empty) (9316433).
- [x] `plans/reports/ops-metric-YYMMDD.md` records the replay over real workers. — Recorded in `plans/reports/ops-metric-261106.md` (`ops_metrics.py --manage-workers`, run alone, 3 rounds, 102 min): pcap 24 jobs and static (`full`) 90 jobs, 0 % failure, 100 % parse success, with queue and run p50 / p95.
- [x] The live-run wrapper is guarded and documented, and its report says run or "not run". — The guard and docs are done: `scripts/live_run.mjs` (+341) refuses without `CYBERLAB_LIVE=1`, `.secrets/live.env`, `--max-calls` and `--max-usd`, and it is documented in its header and in TESTING. Recorded as **not run** in `plans/reports/m7-heavy-steps-261106.md` (no keys and no budget, a user decision). The wrapper was not invoked, so no `live-run-YYMMDD.md` exists.

## Risk Assessment
- **Percentiles on large windows:** the 7 d window over `job_outcomes` uses the `(kind, finished_at)` index. At this scale it is fine; measured in step 2.
- **Live tests' container:** the existing live tests may assume egress. Resolve it before writing the wrapper, and never add egress to `api-test`.
- **Replay memory:** pcap-worker plus static-worker plus the stack is about 6 GB. Run the pcap round and the static round sequentially, stopping the other analyzer.

## Implementation Notes (2026-11-07)
- **Commit:** 9316433 (phases 2–10 together). The 0014 triggers and the `error_classes.py` map are from 980386a and were not edited here.
- **Lane 5:** `scripts/lane-test.sh 5 …` on its own files, plus ruff, format and mypy. The replay was not run (heavy step).
- **Trigger verification** (`test_job_outcomes_triggers.py`, 11 tests):
  - one row per terminal transition, through the lifecycle and the reaper fail paths (pcap and static failed / timeout, TI `expired`, AI `policy_blocked`);
  - renders write a row on `succeeded` / `failed` and none on `purged`;
  - a multi-provider TI run is recorded as `multi`;
  - bad codes and subkinds are sanitized to `other`;
  - no phase-1 bug was found.
- **Trigger cost:** a bulk reaper fail of 500 jobs takes **+2.8 %** with the trigger (the limit is 20 %; interleaved runs, minimum of each), measured by `test_bulk_reaper_fail_cost_of_the_trigger`.
- **Aggregation** (`ops/metrics.py`, +330):
  - windows 1 h, 24 h and 7 d;
  - per (`kind`, `subkind`): counts by status, the failure ratio, `percentile_cont` p50 / p95 / p99 of `run_ms` and `queue_ms`, and parse success through `classify()`;
  - failures by class;
  - active gauges from the `*_index` tables;
  - one statement per window under `SET LOCAL statement_timeout = '2s'`.
- **`render_prometheus`:**
  - exposition format 0.0.4 with HELP and TYPE lines;
  - the label values come from fixed enums only, and error codes are never labels;
  - `prometheus_client` is not in the lock, so `unit/test_prometheus_render.py` uses a strict regex validator.
- **`/internal/metrics`** (`ops/internal.py`), checked in this order:
  1. 404 when no token is configured;
  2. 403 on `X-Forwarded-For` / `Forwarded`;
  3. 60 requests per minute in one global bucket;
  4. 401 without the bearer token (constant-time compare).

  It answers `no-store` and is never routed by the gateway.
- **Group-B review, Low (fixed in 9316433):**
  - The rate limit was keyed per peer, and the peer is what uvicorn derives from the forwarded headers, so a caller could rotate it at will.
  - It is now one global bucket (`metrics:`), and the 403 on forwarded headers comes before the limit, so a proxied request never takes a slot.
  - Tested by `test_rate_limited_in_one_global_window` and `test_a_proxied_request_is_refused`.
- **Org metrics** (`GET /orgs/{org}/ops/metrics?window=`, `audit.read`):
  - the numbers come from the org's tenant tables, never from `job_outcomes`;
  - it lists the five most recent failures with error code, class and deep link (a contract gap field added in 9316433).
- **`scripts/ops_metrics.py`** (standard library only):
  - the datasets are generated into the Docker volume `cyberlab_ops_samples`, never the host disk (host AV);
  - `--manage-workers` runs pcap, then static, one analyzer at a time;
  - the driver is a one-off `api-test` container;
  - it reads the org metrics and `/internal/metrics` inside the api container, so the token never leaves it.
- **`scripts/live_run.mjs`** (network choice, as Step 6 asked):
  - The live tests need egress, and `api-test` has none. So the TI smoke test runs in a one-off `enrich-worker-test` and the AI tests in `analyst-worker-test` (both on `egress`), with `--noconftest`. Egress is never added to `api-test`.
  - The calls are budgeted before anything runs.
  - The report never holds a key or raw provider output.
- **Pending gate:** the replay and its report `plans/reports/ops-metric-YYMMDD.md` (phase 11, run alone).
- **Not done:** the live run and its `live-run-YYMMDD.md`. There are no provider keys or budget: a user decision.
- **Closure (2026-11-06):** The replay ran and is recorded in `plans/reports/ops-metric-261106.md` (0 % failure, 100 % parse success).
