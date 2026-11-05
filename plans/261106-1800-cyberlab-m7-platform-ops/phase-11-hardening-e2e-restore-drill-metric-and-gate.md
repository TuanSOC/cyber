---
phase: 11
title: "Hardening e2e restore drill metric and gate"
status: pending
priority: P1
effort: "16h"
dependencies: [10]
---

# Phase 11: Hardening, e2e, restore drill, metric and gate (group D)

## Overview
Close M7 with:
- the cross-phase pipeline tests (retention end to end through the real worker and MinIO; correlation through real ingest);
- the env and least-privilege checks;
- the security regression;
- the Playwright e2e in dev and prod;
- the restore drill as the last exclusive gate step;
- the M7 metric report, TESTING.md, a reviewer pass and the plan notes.

**Owns:**
- `apps/web/e2e/{search-correlation,retention}.spec.ts`;
- `scripts/{e2e,verify}.mjs` and `scripts/check-retention-worker-env.mjs` (after the stub);
- `apps/api/tests/integration/test_retention_pipeline.py` and `test_correlation_pipeline.py`;
- `docs/TESTING.md` (the M7 results);
- `plans/reports/ops-metric-YYMMDD.md` (the gate addendum);
- the "Implementation Notes" of every phase file.

Fixes found here go into the owning files one at a time, coordinated by the parent. This is the only phase allowed to touch other phases' files, and only for gate fixes and the seam items below.

## Requirements
- **Seam items from group B:**
  - assert every `PENDING_ROUTES` set is empty;
  - `pnpm gen:contracts` shows no drift;
  - the phase-1 slot mounts are intact and filled by phases 8 and 9 (RT16);
  - the `MINIO_IMAGE` default is the parent's choice (or bitnami with the residual recorded).
- **Retention pipeline** (`test_retention_pipeline.py`, with the real `retention-worker-test`, broker, MinIO test buckets and API):
  1. Seed an aged closed case (pcap and static jobs, a render, TI and AI rows, one TI row and one AI run cited by a report, a TI result reused by a recent `cached` item, an AI run tree). Set a policy and `enforce` through the API, with backdated `effective_at` and `enforce_effective_at` set by the test as the owner.
  2. Run `POST /retention/preview`, then `POST /retention/runs` (enforce) through the broker.
  3. Assert:
     - the purged set equals the preview;
     - evidence answers 410, the hashes and custody (with `purged`) remain, and the run items and audit rows exist;
     - cited TI and AI rows remain, the reused TI result and the partly recent AI tree remain; the snapshot remains and verifies; the render is `purged` and a re-render succeeds;
     - the correlation keys of the case **remain** and still show in "also seen in" (RT9);
     - the custody `purged` events carry the system user, which cannot log in (RT12).
  4. A case hold placed before the run → untouched at both the DB and the S3 legal hold level.
  5. An org hold → the run is `skipped_hold`.
  6. A lowered policy without the backdate → nothing purged; `enforce` turned on without the backdate → the run is dry-run; a hold released yesterday → its case untouched (RT1).
  7. The daily sweep (beat) finds the org through `retention_policy_index` (RT3).
- **Correlation pipeline** (`test_correlation_pipeline.py`):
  - two real pcap jobs from the dataset in two cases sharing an IP and a domain, plus a static job whose sample sha256 equals an evidence hash in another case;
  - after one beat interval: "also seen in", related cases and search return them; another org's identical data never appears.
- **Least privilege** (`scripts/check-retention-worker-env.mjs`, in `verify:prod`):
  - the rendered dev, test and prod configs give the retention worker only its DB URL, broker URL, purge MinIO keys and settings: no JWT secret, seal or signing keys, app Redis or api MinIO keys;
  - no other **runtime** service holds the purge keys or the retention DB password (the test-profile `api-test` and `e2e` legitimately hold the test equivalents, as they already hold the MinIO root, RT27);
  - the api MinIO policy has no legal-hold action (RT5);
  - `/internal/metrics` is not routed by Caddy;
  - the KMS secret is mounted on minio only, and prod refuses the dev KMS key name and the dev metrics token.
- **Security regression:**
  - the IDOR enumerator with the three new modules;
  - RLS coverage and append-only (strict vs exception) for 0014;
  - the M4–M6 suites still green with SSE-S3, the global rate limit at test values and the new triggers;
  - the type-mismatch and view-audit suites;
  - a crawler that asserts no new route leaks the search query into logs or URLs (search is POST-only, RT13);
  - a CSP e2e unchanged.
- **E2E:**
  - **`search-correlation.spec.ts`:**
    1. Register, then two cases each with the e2e pcap (or a second small dataset pcap).
    2. Wait for the analyses.
    3. The header search for the shared domain → observable and finding hits, and a deep link works; the page URL carries the query only in its fragment.
    4. The IOC tab shows "seen in 1 other case"; the drawer lists the other case; the case page "Related cases" shows it.
    5. A hostile query string renders inert.
  - **`retention.spec.ts`:**
    1. As admin, open Settings → Retention, set the values (the floor is enforced in the UI) and see the pending notice.
    2. Preview shows counts.
    3. Place a case legal hold → the badge is shown.
    4. A seeded purged evidence (seeded through an e2e-only API helper or the owner SQL step in `e2e.mjs`) shows the purged strip, and download is disabled.
    5. Operations shows the e2e jobs.
    6. The viewer sees no actions.
  - **prod e2e:** the same specs on the prod stack. The gate asserts the retention worker runs with `ENV=prod` and the env check passes.
  - Run the e2e once with the real dev default `RATE_LIMIT_USER_PER_MIN` (600) to prove the UIs stay under it.
- **Verify gate** (`scripts/verify.mjs`):
  - build and reload `retention-worker(-test)`;
  - run `db-bootstrap` before the migrations;
  - the new API suites, the pipeline tests, `check-retention-worker-env.mjs` (`--prod`) and the object-store conformance suite against the current image;
  - **last step, exclusive:** after the e2e and `prod:down` (without `-v`), and **before** the `finally` that brings the dev stack back, run `pnpm restore:drill` (`--prod` in `verify:prod`) with nothing else running, and record its timings. The drill's `down -v` guard test (`stack.test.mjs`, RT2) runs earlier with the node unit tests.
- **Metric** (§14, recorded in `plans/reports/ops-metric-YYMMDD.md` (the gate addendum) and TESTING.md):
  - from the gate run's `job_outcomes`: the failure rate, p50 / p95 latency and parse success per analyzer, next to phase 5's replay numbers;
  - restore drill: backup (with drain), restore and verify durations, sizes, and the objects verified per phase (`--db`, `--objects`, `--rls`; floor: 0 mismatches);
  - retention: the dry-run ≡ enforce equality (floor 1.0) and 0 strict-table deletions;
  - search: the p95 per type from phase 4;
  - live runs: the phase-5 status (run / not run).
- **Reviewer pass:**
  - the purge paths and the append-only exception;
  - the backup / restore scripts (path handling, refusal logic, secrets);
  - the internal metrics endpoint;
  - the rate limit;
  - the search query handling;
  - the UI wording (purge, legal hold, correlation).

  No open High findings.
- **Plan notes:** every phase file gets "Implementation Notes", and success criteria are ticked only with evidence (a test name or a gate log). The plan frontmatter becomes `completed` only after the gate passes and the branch merges. Write the M7 row in ROADMAP only then (coordinated with phase 10's draft).

## Implementation Steps
1. The seam items; regenerate the contracts; fix seams in the owning files.
2. The retention and correlation pipeline tests; fixes.
3. The env check and the security regression.
4. The e2e specs and the `e2e.mjs` changes (the purged-evidence seed step); run in dev and prod, and once at the default rate limit.
5. The `verify.mjs` update with the drill as the last exclusive step; `pnpm verify:prod`.
6. The metric addendum and TESTING.md.
7. The reviewer pass and the plan notes.

## Success Criteria
- [ ] `pnpm verify:prod` is green, including the restore drill as its last exclusive step with 0 mismatches.
- [ ] Retention purges exactly the previewed set through the real worker, respects case and org holds at the DB and S3 level, keeps cited and strict data, and lets a purged render re-render.
- [ ] Correlation and search work across cases on real ingested data and never across orgs.
- [ ] The least-privilege env checks pass for dev, test and prod.
- [ ] The metrics are recorded with their floors met, the reviewer pass has no open High findings, and the plan notes are written.

## Risk Assessment
- **Gate memory and time:** the drill runs after everything else is down. The analyzers stop after their e2e steps if the host is tight.
- **E2E needing aged data:** seed the purge state through an explicit e2e-only owner step in `e2e.mjs`, never through a production API path.
- **Seam fixes across many owners at the end:** one commit per fix in the owning file, coordinated by the parent.
