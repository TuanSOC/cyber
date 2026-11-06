---
phase: 7
title: "Memory read API"
status: pending
priority: P2
effort: "10h"
dependencies: [1]
---

# Phase 7: Memory read API (group B, 2f, lane 7)

## Overview
Read routes over one memory job's persisted results, on the M3 `static_analysis/router.py` pattern (`evidence.read`, RLS, keyset pagination, capped pages). Findings, IOCs and timeline already have generic routes (`pcap_analysis/router.py`: `/findings`, `/iocs`, `/timeline`); they work for memory jobs unchanged.

**Owns:**
- `app/modules/memory_analysis/{router,repository,service}.py` (after the phase-1 stubs; the schemas are frozen in `memory_analysis/schemas.py`);
- `tests/security/idor_cases_memory.py` (fills the phase-1 `PENDING_ROUTES` of the six phase-7 routes; the sensitivity routes are in phase 8's `idor_cases_memory_sensitivity.py`, RT24);
- `tests/integration/test_memory_reads.py`, `test_memory_process_tree.py`.

## Requirements
- **Routes** (all `GET`, under `/api/v1/orgs/{org_id}/analyses/{job_id}/memory`, `evidence.read`; `404` for a non-memory job and for another org's job; `409 analysis_not_ready` while queued or running):

  | Path | Returns |
  |---|---|
  | `` (the summary) | `MemorySummaryOut`: trusted evidence hashes, image facts (OS, arch, build or banner, layer, system time), symbols status and requirement, the Volatility version, the engine (`volatility3` / `replay`), the audit-hook counts, per-plugin status (ok / failed / timeout / skipped / unsupported, rows, truncated, duration), counts, the sensitivity state from phase 8 (read only) |
  | `/processes?view=list\|tree&q=&cursor=` | `ProcessPage`: pid, ppid, name, create / exit time, threads, handles, session, wow64, `sources` (pslist / psscan / pstree), cmdline (≤ 4 KiB), image path, flags (`hidden`, `terminated`, `injected`, `lineage_anomaly`, from the findings) |
  | `/processes/{pid}` | one process with its connections, injections and artifacts (each capped at 200, with totals) |
  | `/connections?state=&pid=&cursor=` | `ConnectionPage` |
  | `/injections?pid=&cursor=` | `InjectionPage` (hex head ≤ 64 bytes, disassembly ≤ 1 KiB, both as text) |
  | `/artifacts?type=module\|service\|hive\|userassist\|ldr_unlinked\|bash\|open_file\|syscall_hook\|hidden_module&pid=&cursor=` | `ArtifactPage` |

- **Tree view:** built server-side from `memory_processes` (ppid links, cycles broken, orphans at the root with `parent_missing`), at most `MEMORY_TREE_MAX_NODES` (5 000) nodes; beyond that `truncated: true` and the list view.
- **Bounds:** page size ≤ 200; `q` 1–128 characters, a prefix / substring match on name and cmdline inside the job (the job's rows only, never org-wide); `SET LOCAL statement_timeout = '5s'`.
- **Output safety:** every text field is returned as stored (bounded, NUL-free); the web renders text only. Hex and disassembly are strings, never bytes.
- **No audit per read** beyond the M7 evidence view audit (the job page is a derived view; recorded decision, same as static).
- **IDOR:** every route in `idor_cases_memory.py` (cross-org job id, a pcap job id, an unknown pid).

## Implementation Steps
1. Read the M3 static router, repository and pagination helpers.
2. Repository queries per table with keyset cursors; the tree builder (pure function, unit-tested with cycles and orphans).
3. Router and service; error mapping.
4. IDOR cases; integration tests seeded through the phase-1 helper `seed_memory_job()` (a canned ingest of the phase-1 fixture).
5. Lane 7 tests, `ruff`, `mypy`.

## Success Criteria
- [ ] Every route answers from the seeded job with correct pagination and filters, and `404` across orgs and for non-memory jobs.
- [ ] The tree view renders cycles and orphans without recursion errors and truncates beyond 5 000 nodes.
- [ ] `idor_cases_memory.py` has no pending route.

## Risk Assessment
- **Large artifact tables** (Linux `lsof` in the `full` profile; `windows.handles` is cut, RT9): keyset pagination on `(job_id, type, id)` and the per-kind caps keep pages cheap.
- **Schema drift:** the response models are frozen in phase 1; the web builds against them.
