---
phase: 8
title: "Re read api"
status: code-complete (untested in Docker)
priority: P2
effort: "10h"
dependencies: [1]
---

# Phase 8: RE read API (group B, 2g, lane 7)

## Overview
Read routes over one RE job's persisted results, on the M3 / M8 router pattern (`evidence.read`, RLS, keyset pagination, capped pages), plus the reverse link from a static capability to its functions. No call-graph route (RT24: callers and callees in the function detail give the navigation). Findings and IOCs use the existing generic routes.

**Owns:** `apps/api/app/modules/reverse_engineering/{router,repository,service}.py` (after the phase-1 stubs; schemas frozen), the `GET /analyses/{static_job}/capabilities/{id}/functions` route in `static_analysis/router.py` (its handler lives in `reverse_engineering/service.py`), `tests/security/idor_cases_reverse.py` (fills the phase-1 `PENDING_ROUTES`), `tests/integration/test_re_reads.py`, the `functions` count of `CapabilityLinkedOut` (RT6).

## Requirements
- **Routes** (all `GET`, under `/api/v1/orgs/{org_id}/analyses/{job_id}/reverse`, `evidence.read`; `404` for a non-reverse job and another org's job; `409 analysis_not_ready` while queued or running; `{entry}` is a decimal string, validated `0 ≤ x < 2^64`, `404 function_not_found` otherwise):

  | Path | Returns |
  |---|---|
  | `` (summary) | `ReSummaryOut`: trusted evidence hashes, the source static job (id, link), program facts, engine and versions, code kind, stage statuses and durations, peak container memory per stage, audit counts, the effective JVM arguments, counts, truncation flags, `capa_linked` / `capa_unlocated`, decompile budget used |
  | `/functions?q=&decompiled=&has_capability=&calls_suspicious=&refs_ioc=&sort=entry\|size\|rank\|name&cursor=` | `FunctionPage`: entry (string), RVA, name, name source, size, flags, signature, callers / callees counts, decompile status, rank, capability count, finding count |
  | `/functions/{entry}` | `FunctionDetailOut`: the function plus callers and callees (≤ 200 each with totals), imports called, strings referenced (≤ 200, values as stored), linked capabilities (name, namespace, ATT&CK ids), findings citing it, why it was or was not decompiled (rank or `not_prioritized` / `budget` / `thunk` / `library`), and the newest RE job of the same sample when it is newer than this one (for "Decompile this function" follow-ups, RT10) |
  | `/functions/{entry}/code` | `FunctionCodeOut`: status, code kind, code (≤ 64 KiB, as stored), lines, sha256, truncated; `Content-Type: application/json` only (never `text/html`), `Cache-Control: no-store` |
    | `/imports?library=&q=&cursor=` | `ImportPage` with per-import caller counts |
  | `/strings?q=&has_refs=&cursor=` | `StringPage` with per-string referencing-function counts |
  | `/analyses/{static_job}/capabilities/{id}/functions` | `CapabilityFunctionsOut`: for each succeeded RE job sourced from that static job, the linked functions (≤ 50 per job, newest job first) |

- **Bounds:** page size ≤ 200; `q` 1–128 characters, a substring match on name (functions, imports) or value (strings) within the job only; `SET LOCAL statement_timeout = '5s'`.
- **Output safety:** text as stored (bounded, NUL-free); entries and addresses as strings; no route renders code or names into HTML; the code route is JSON. No audit per read beyond the M7 evidence-view audit (same decision as static and memory).
- **IDOR:** every route in `idor_cases_reverse.py` (cross-org job id, a static job id on the reverse routes, a reverse job id on the capability route, an unknown entry).

## Implementation Steps
1. Read the M3 static router / repository and the M8 memory read API.
2. Repository queries with keyset cursors on (`job_id`, sort key, `entry`); filters through indexed columns and EXISTS subqueries on the ref tables.
3. Router and service; error mapping.
4. IDOR cases; integration tests seeded with `seed_re_job()`.
5. Lane 7 tests, `ruff`, `mypy`.

## Success Criteria
- [ ] Every route answers from the seeded job with correct pagination, filters and caps; `404` across orgs and analyzers.
- [ ] Callers / callees of a 10 000-edge hub function stay within the 200-item caps with correct totals.
- [ ] `idor_cases_reverse.py` has no pending route.

## Risk Assessment
- **Filter cost on 20 000 functions with 50 000 refs:** EXISTS on indexed (`job_id`, `function_entry`) columns; measured at every cap in phase 12.
- **Precision of 64-bit addresses in JS:** strings everywhere in the API (tested by a > 2^53 entry).

## Notes (as built, untested in Docker)

Code-only (no container ran). Host checks: the app imports and serves the same 7 paths; every repository query compiles with the Postgres dialect (23 statements, the EXISTS filters correlate to `re_functions`); the read-model mapping (hex addresses incl. 2**64 - 16, import / string function lists, stages) round-trips; `test_idor_routes` route-coverage tests, `test_m7_foundation::test_no_route_still_raises_the_501_stub` and the foundation route test pass on the host.

**Schemas: unchanged** (phase-1 frozen `reverse_engineering/schemas.py` and the route signatures / query parameters; for phase 10). Behaviour the frontend should know:
- Pagination is the shared **offset** pagination (`limit` <= 100, `offset` <= 10 000, `total` capped at 10 001), not keyset: the phase-1 stubs froze `PageParamsDep`. No `sort` parameter (frozen route): functions are ordered by `priority_rank` (unranked last), then entry; imports by library, name; strings by address.
- `GET …/functions`: FID library functions are hidden unless `include_library=true` (or `ref=` is given). `calls_suspicious_import` = calls an import named in the static report's `NOTABLE_FUNCTIONS` (A / W variants); `references_ioc_string` = references a string containing one of the job's URL / domain / IP / email IOC values. `priority_reason` is derived from stored facts for ranked functions only (requested -> entry_or_export (program entry or an `export` name) -> capability -> suspicious_import -> ioc_string -> size).
- `GET …/functions/{entry}`: lists <= 200; the function's `callers` / `callees` counts are the totals; `imports[*]` / `strings[*]` there carry no function lists; `finding_ids` = findings whose `attributes.function_entry` is the `0x…` entry.
- `GET …/functions/{entry}/code`: **new error code `404 code_not_available`** when the function exists but has no decompiled line (not selected, or `timeout` / `failed` / `skipped_budget` without code: those statuses are in the function detail's `decompilation`). `Cache-Control: no-store`, JSON only. *Addition, not a schema change; `http-errors.ts` may want the code.*
- `GET …/reverse` (summary): `counts` = `re_programs.counts` overlaid with the job summary's (incl. `capa_linked`, `capa_unlocated`, `capabilities_linked`); `newer_job_id` = the newest later RE job of the same evidence that did not fail; a diagnostic (`unsupported_*`) job has a summary; a failed job without a program row answers `404 results_not_available`.
- `GET /analyses/{static_job}/capabilities/{id}/functions`: the newest succeeded RE job sourced from that static job only (`re_job_id`), <= 50 functions by entry; `unlocated` = locations no listed function body contains (all of them without an RE job or a capa base). `CapabilityLinkedOut.functions` on the capabilities list: distinct linked functions in that same newest job; `null` when there is none.
- Every read sets `statement_timeout = 5s`; `409 analysis_not_ready` while queued / running; 404 across orgs and analyzers (an RE job id on the capability route, a static job id on the RE routes).

**Tests:** `tests/integration/test_re_reads.py` (real ingest of `pe_full` through phase 7 + seeded jobs: summary and newer job, states, filters, reasons, detail, code, imports / strings, capability links both ways, cross-org, a 10 000-caller hub, addresses above 2**53); `tests/security/idor_cases_reverse.py` (all 7 routes, `PENDING_ROUTES` empty, `{capability_id}` a resource parameter); `test_m10_foundation.py` (routes answer 404 for an unknown job instead of 501).

**Remains (Docker):** `scripts/lane-test.sh 7 uv run pytest -q -p no:cacheprovider tests/integration/test_re_reads.py tests/integration/test_m10_foundation.py tests/integration/test_static_capa_locations.py tests/security/test_idor_routes.py tests/integration/test_m7_foundation.py`; `ruff`, `mypy`; `pnpm gen:contracts` after the merge (route descriptions changed; no schema change); filter cost at every cap in phase 12 (`references_ioc_string` is a `strpos` join over the job's IOCs).
