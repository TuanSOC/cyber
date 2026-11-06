---
phase: 8
title: "Re read api"
status: pending
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
