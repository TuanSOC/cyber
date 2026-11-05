---
phase: 11
title: "Hardening e2e metric and gate"
status: pending
priority: P1
effort: "10h"
dependencies: [8, 9, 10]
---

# Phase 11: Hardening e2e metric and gate (group D, 4)

## Overview
Close M5:
- the end-to-end pipeline tests across the merged phases;
- the egress, isolation and key-leak suites;
- the security regression additions;
- the "AI evidence citation accuracy" metric and the prompt-injection results;
- the Playwright e2e on `mock` (and the refusal in prod);
- the verify gate, TESTING.md, the final doc reconciliation, a reviewer pass and the plan notes.

**Owns:**
- `apps/web/e2e/ai-analyst.spec.ts`;
- `scripts/{e2e,verify}.mjs`, `scripts/check-analyst-env.mjs`, `scripts/check-ai-key-leak.mjs`;
- `apps/api/tests/integration/test_ai_pipeline.py`, `test_ai_key_leak.py`;
- `apps/api/tests/container/test_egress.py` and `test_analyst_network.py` additions;
- `packages/py-worker-kit/tests/test_isolation.py`;
- `docs/TESTING.md`, `plans/reports/ai-metric-YYMMDD.md`;
- the "Implementation Notes" of every phase file.

Fixes found here go into the owning files one at a time, coordinated by the parent; this is the only phase allowed to touch other phases' files, and only for gate fixes.

## Requirements
- **Pipeline tests** (`test_ai_pipeline.py`, real API + analyst-worker-test + ai-mock + DB + broker):
  - for every task: request → worker → `completed` with verified citations;
  - an incident with 2 jobs → children → reduce → timeline entries carry record timestamps;
  - 429 marker → `waiting` → beat resume → `completed`;
  - refuse marker → `refused` (category shown);
  - spend → `failed/spend_limit`; maxtokens; malformed → repair → `invalid_output`;
  - echo → `canary_leak`, body withheld by the API;
  - fabricate → invalid citations, unsupported claims hidden;
  - inject → no link, verdict flag;
  - budget exhausted (tiny org budget);
  - org disables AI mid-run → `failed/ai_disabled`;
  - the deadline and the fallback reaper;
  - `ai-mock:slow` just under the call timeout → `completed` (no transaction held across the call, RT7); beyond it → full reservation charged, at most `AI_MAX_CALLS_PER_RUN` calls seen by ai-mock (`GET /_last` counter), then `failed/provider_error` (RT2);
  - an incident whose children exceed the org's free slots → `409 ai_busy` before anything is created (RT8);
  - broker restart (FLUSHDB of the broker test db) mid-day → the next run's reservation is seeded from the DB, and the budget still holds (RT9).
- **Outbound privacy test:** ai-mock records request bodies (test-only endpoint `GET /_last` on the egress-only mock). For a seeded case with RFC 1918 hosts, internal hostnames, `C:\Users\alice` paths and URL query tokens, assert that none appears in the body when pseudonymization is on, and that the credential fields are never present.
- **Egress and isolation:**
  - api-test, ingest and the analyzers cannot resolve or reach `ai-mock` or the analyst-worker;
  - `analyst-worker-test` has a default route, reaches `ai-mock`, and is not on `analysis`/`backend` (cannot resolve `api`, `redis`, `minio`, `pcap-worker-test`);
  - `scripts/check-analyst-env.mjs` renders dev, test and prod configs: no `JWT_SECRET`, `MINIO_*`, `REDIS_URL` or `TI_SEAL_PRIVATE_KEYS_FILE` in analyst; no `AI_SEAL_PRIVATE_KEYS_FILE` / `AI_PLATFORM_KEY_FILE` anywhere else; prod has `ENV=prod`, the prod image and no mock or platform key;
  - the gate asserts the prod analyst-worker is `running 0` (no restarts) after 15 s.
- **Key-leak suite:** a sentinel AI key set through the API must be absent from:
  - every API response (a crawl of the AI routes and of routes embedding AI data) and `audit_logs.details`;
  - api, analyst-worker, ingest and ai-mock logs (`scripts/check-ai-key-leak.mjs`), including a run where ai-mock echoes the key in a 401;
  - broker message bodies while a run waits;
  - `ai_run_inputs`, `ai_outputs` and `ai_citations`;
  - reprs of providers, clients and errors.

  Also check that no TI private key is loadable in analyst and no AI private key in enrich.
- **Security regression:**
  - RLS coverage and the IDOR enumerator include every AI table and route, plus the phase-4 routes;
  - ACL tests for `analyst`; the import guards; config and prod-guard tests;
  - the TI seal tests and the pre-refactor fixture still green;
  - HostileProvider invariants at exact floors (`test_ai_eval_invariants.py`, now over the merged pipeline);
  - property tests for sanitize, defang and pseudonymize;
  - CSP e2e unchanged.
- **Metric** ("AI evidence citation accuracy", §14):
  - run `scripts/ai_eval.py` on FakeProvider (pipeline sanity), HostileProvider (invariants) and Replay (if cassettes exist);
  - if a key is available locally, `AI_EVAL_LIVE=1 … --runs 3 --record --write` for Anthropic (`claude-sonnet-5`; optionally `claude-opus-5-5`) and Gemini if billing is configured;
  - record in `plans/reports/ai-metric-YYMMDD.md` and TESTING.md: citation accuracy, unsupported-claim rate, invalid-ref rate, ATT&CK precision and invalid count, golden recall, refusal rate, ASR per payload P1–P8, utility under attack, tokens, cost, latency p50/p95;
  - label each number **live**, **replayed (recorded on date X)** or **fake (pipeline only)**. No live key → say so explicitly; the CI floors still apply.
- **E2E** `apps/web/e2e/ai-analyst.spec.ts`:
  - **dev:**
    1. Register → Integrations → enable AI (privacy acknowledgement) → acknowledge the mock terms → set the mock key → verify `valid`.
    2. Upload the e2e pcap → AI Analyst tab → preview shows counts and pseudonyms → Summarize → passes `waiting` (a dataset value carrying `ai-mock:429`) → `completed` within 90 s.
    3. Observed claims show verified chips; click a chip → findings tab filtered to that row.
    4. Explain on a finding row opens the drawer with output.
    5. A hostile case (dataset value with `ai-mock:inject` + `ai-mock:fabricate`) → no anchor elements inside the output except verified chips, the unsupported counter visible, the verdict note shown.
    6. Investigation → Incident summary → timeline and recommendations visible.
    7. The AI runs list shows the runs.
    8. No console errors; no key in `page.content()`.
  - **prod e2e:** the providers catalog shows mock unavailable and `PUT` → 422; the flow is skipped with a reason; the gate asserts the analyst-worker runs with `ENV=prod`.
  - `scripts/e2e.mjs` starts `ai-mock` (profile `e2e`) with `AI_MOCK_EXPECTED_KEY`; the e2e dataset gets the marker values (generated, not committed).
- **Verify gate** (`scripts/verify.mjs`):
  - reload `analyst-worker`, `analyst-worker-test` and `ai-mock`;
  - run the analyst network test in `analyst-worker-test`, the key-leak log scan and `check-analyst-env.mjs` (`--prod`);
  - live AI tests and `AI_EVAL_LIVE` are never in the gate.
- **Docs:** TESTING.md (M5 suites, floors, metric table); reconcile the phase-10 docs with the final UI wording and gate facts.
- **Reviewer pass:** analyst-worker, sealing refactor, context builder (privacy), verifier, API, frontend rendering. No open High findings.
- **Plan notes:** every phase file gets "Implementation Notes", and the success criteria are ticked only with evidence (a test name or a gate log).

## Implementation Steps
1. The pipeline and outbound-privacy tests; fix seams in the owning files.
2. The egress, isolation, env-check and key-leak suites.
3. The metric runs and the report; TESTING.md.
4. The e2e spec and `e2e.mjs` changes; run in dev and prod.
5. The `verify.mjs` update; `pnpm verify:prod`.
6. Doc reconciliation, the reviewer pass, the plan notes.

## Success Criteria
- [ ] `pnpm verify:prod` green: the dev e2e runs the AI flow on mock; the prod e2e asserts mock refused and the analyst-worker `ENV=prod`, `running 0`.
- [x] The outbound-privacy test proves no internal IP, hostname, username, URL query value or credential leaves with pseudonymization on. (`test_ai_pipeline.py::test_nothing_internal_leaves_with_pseudonymization_on`)
- [x] The sentinel key is absent everywhere listed; the role separation (TI vs AI private keys) is proven. (`test_ai_key_leak.py`, `scripts/check-ai-key-leak.mjs` "sentinel absent", `test_analyst_network.py::test_its_environment_holds_no_api_secrets_or_ti_keys`, `test_enrich_network.py::test_it_holds_no_ai_private_key`, `scripts/check-analyst-env.mjs`)
- [x] HostileProvider invariants are at exact floors; the metric is recorded with honest provenance labels (live / replayed / fake). (`scripts/ai_eval.py`: 1220 hostile runs, 0 violations; `plans/reports/ai-metric-261105.md`)
- [ ] The reviewer pass has no open High findings; docs are reconciled; plan notes are written.

## Risk Assessment
- **No live key available.** The metric is then replay- or fake-only. That is acceptable for the gate but stated plainly in TESTING.md and the report.
- **Flaky e2e timing** around waiting/resume (beat 30 s). Use `Retry-After: 1` and give the wait the same 90 s bound as M4.
- **Seam fixes across many owners at the end.** Keep each fix in the owning file and commit per fix, coordinated by the parent.

## Implementation Notes

- **Review fixes landed here:** `?reveal=true` on the context route needs `evidence.write` (viewers 403; the reveal stays audited; the web toggle is hidden for viewers); an unbilled 429 / 529 gives its call back (`_refund_call`), so a rate limit at the call cap parks the run until the deadline and overloads end on the backoff schedule (4 attempts) instead of `provider_error`; the provider PUT takes `limits: {per_minute}` within the ceiling (`422 limit_above_ceiling`, `{}` resets; read model `default_limits` / `ceilings` / `limits`; a small form on the provider card); the stale compose comment.
- **ai-mock:** it never parsed the real prompt (`ai.prompt.render` sends an items array and names the task in the user turn; only the test doubles' context object was understood), so every real run got the empty answer; fixed and covered (`test_the_default_answer_reads_the_real_prompt`). `echo` now echoes the user turn up to the evidence (where the canary is); new markers `429-once-<label>` (e2e wait) and `hostile`; `401` echoes the key (key-leak suite); the `/_last` snapshot is mirrored to the `ai_mock_state` volume, read-only in api-test, because api-test cannot reach ai-mock (egress only) and must not.
- **Test worker:** `analyst-worker-test` runs with `AI_CALL_TIMEOUT_S=8`, so the RT2 / RT7 slow-call tests take seconds. The pipeline and key-leak tests run on the default lane only (the worker serves `cyberlab_test` and broker db 1); lanes 2–7 skip them.
- **Deadline:** `ai_runs.deadline_at` is immutable (trigger), so the deadline test sets the API's `ai_run_deadline_s` to its 60 s minimum before the request. The fallback reaper is not exercised end to end (covered in `test_analyst_worker.py`).
- **RT8 (`409 ai_busy`)** stays covered by `test_ai_api_runs.py`; RT9 is proven by deleting the day key mid-day (the test user cannot FLUSHDB the broker).
- **E2E:** six specs now register a user each, over the 5 per 10 min per-IP limit: `scripts/e2e.mjs` runs them in batches of five and clears the register keys before each batch. The prod check asserts the mock card is absent (the UI hides unavailable mocks), the catalog says `prod_mock` and the PUT answers 422.
- **Snapshot:** `ai_eval_snapshot.py` replaced the hand-trimmed cases with pipeline ones; real ClamAV names carry `.UNOFFICIAL` (two golden files updated) and the static worker's analysis-time stamps are pinned in `tests/ai_eval/snapshot.py`.
- **Open:** `pnpm verify:prod` (run by the parent), the reviewer pass, and the Implementation Notes of phases 1–10.
