---
phase: 3
title: "Data retention purge and legal hold"
status: pending
priority: P1
effort: "23h"
dependencies: [1]
---

# Phase 3: Data retention purge and legal hold (group B, 2b, lane 3)

## Overview
The §13 data retention: per-org policies (three knobs), a dry-run preview, legal holds mirrored to S3 legal hold, and the least-privilege retention worker. The worker purges only expired, unheld and uncited data, tombstone first, and audits every purge. The design is in plan.md "Retention, purge and legal hold".

**Owns:**
- `app/modules/retention/**` (after the phase-1 stubs and models): `service.py`, `repository.py`, `select.py`, `holds.py`, `policy.py` (effective values and `enforce` with the delay), `objects.py` (the purge-user client: S3 legal-hold sync and deletes), `router.py`;
- `app/workers/{retention_app,retention_tasks,retention}.py` (after the stubs);
- `evidence/{service,repository,transfer}.py`: the `purged_at` / `legal_hold` read fields, and `410 evidence_purged` on download and verify (after the org check, so another org's evidence still answers 404);
- `analysis/service.py`: one guard, `410 evidence_purged` when an analysis is requested on purged evidence;
- `investigations/{service,repository}.py`: `legal_hold` on case reads, and the hold check on archive (unchanged semantics; flag only);
- `app/scripts/reconcile_orphans.py`: tombstoned versions are reported as `purged_pending_delete`, not as orphans; a pinned version missing **without** a tombstone is reported as `missing_unexplained` (RT5);
- `tests/security/idor_cases_retention.py`;
- `tests/integration/test_retention_{policy,holds,preview,purge,objects,append_only_exception,runs}.py` and `tests/unit/test_retention_select.py`.

## Requirements
- **Policy** (`GET` / `PUT /retention/policy`):
  - **Fields:** `ti_results_days`, `ai_runs_days`, `closed_case_days`, each `int | null`, and `enforce: bool`.
  - **Floors:** 30 for TI and AI, max(30, `EVIDENCE_LOCK_DAYS`) for closed cases → `422 policy_floor`.
  - **Effective values:**
    - lowering a value (including null → a number) stores `pending_<field>` with `effective_at = now + RETENTION_POLICY_DELAY_DAYS`;
    - raising one, or setting it to null, applies at once and cancels a pending lower;
    - the read returns `current`, `pending` and `effective_at`.
  - **`enforce: true`** needs `acknowledge_destruction: true` → `422 retention_acknowledgement_required`. **It takes effect after the delay (RT1):** stored as `pending_enforce` with `enforce_effective_at = now + RETENTION_POLICY_DELAY_DAYS`; turning it off applies at once and cancels a pending on. A pending lowered value keeps its own date.
  - **The system lookup (RT3):** every PUT upserts `retention_policy_index` (org id, `updated_at`) in the same transaction.
  - **Audit:** `retention.policy_changed` (before / after / pending) and `retention.enforce_changed` (requested and effective dates).
- **Legal holds:**
  - `POST /legal-holds {scope, investigation_id?, reason}`; `POST /legal-holds/{id}/release {reason}`; `GET /legal-holds?active=`.
  - **Audit:** `legal_hold.placed` and `legal_hold.released`.
  - **A case hold (RT5):** after the commit, the API publishes `retention.sync_holds(org_id)` and answers `s3_sync: pending`. The retention worker (purge user, which holds `PutObjectLegalHold`; the api user holds none) sets the S3 legal hold ON for every evidence version of the case and every report snapshot of reports on that case, bounded per task (≤ 500 objects; the rest by the next run), and stamps `legal_holds.s3_synced_at`.
  - **Release:** recorded at once (audit, `released_at`), but the hold **keeps protecting** until `released_at + RETENTION_POLICY_DELAY_DAYS` (RT1): the selector treats it as active, and the sync turns S3 hold OFF only after that, for objects no longer covered by another hold (org or case).
  - **An org hold:** no S3 calls (it would touch every object). The selector and the worker skip the org entirely, and the reconcile step sets nothing. Documented.
  - **Effect:** a case or an org under hold is excluded from every category. `EvidenceOut.legal_hold` and the case `legal_hold` are true.
- **Selector** (`select.py: candidates(...)`, read-only; the API preview and the worker share it):
  - **`ti`:** `ti_results` with `created_at < now - days`, excluding rows referenced by `report_citations` (`ref_table` / `ref_id`) and rows of held cases. TI rows tied to a case's job scope follow that case's hold; manual lookups have no case and are only age-based. **FK rule (RT10):** `ti_run_items.result_id` references the result (and a `done` / `cached` item must keep it), and later runs reuse old results as `cached`; a result is eligible only when every item referencing it belongs to a run finished before the cutoff. Those items are deleted first, then the result; the run rows stay.
  - **`ai`:** `ai_runs` in a terminal status with `finished_at < now - days`, excluding runs whose citations or outputs are referenced by any `report_citations` (the `ai_citation_id` or `ref_table` / `ref_id`) and runs scoped to held cases. **Run trees (RT10):** runs linked by `parent_run_id` / `supersedes_run_id` are selected as a whole tree, only when every member is eligible and uncited. Children are deleted explicitly in FK order (citations, outputs, context refs, inputs, then the runs; `ai_run_index` cascades); a cascade into an append-only table would be refused, by design.
  - **`closed_case`:** cases whose latest status event moved them to `closed` or `archived` at least N days ago and that are still closed or archived (a reopened case is excluded). A case with **no** status event (closed before M6) is never selected, and a case with a queued or running job is skipped this run (RT24). Per case:
    - evidence versions without a tombstone whose `retain_until` (from MinIO, checked at purge time) has passed;
    - the bulk rows of its jobs, counted per table, except rows cited by `report_citations` (`ref_table` / `ref_id`), kept as `kept_cited` (RT23);
    - `results` object versions of its jobs;
    - `succeeded` renders of its reports, never snapshots.

    Its `correlation_keys` are **kept** (RT9): they derive from kept rows and carry the cross-case pivot.
  - **Output:** a `CandidateSet` with counts and bytes per category, plus a bounded sample (≤ 50 per category, ids and labels only).
  - **Determinism:** the same seed and `now` give the same set.
- **Preview** (`POST /retention/preview {as_of?}`, `org.update`): run the selector with the **effective** policy (or `include_pending=true` to show what the pending values would add). Writes a `retention_runs` row `mode=dry_run, trigger=manual` with its counts and sample. Audited `retention.previewed`.
- **Runs:**
  - `GET /retention/runs` and `/{run}` (with paged items).
  - `POST /retention/runs` (`org.update`; `mode` dry-run or enforce; enforce requires the policy's `enforce=true`, and only categories with an effective value run) publishes `retention.run_org` after the commit.
- **Worker** (`workers/retention.py`, `PROCESS_ROLE=retention`):
  - **`sweep()`:** for each org in `retention_policy_index` (a system session; RT3: RLS binds the role and `organizations` shows it no org), enqueue `run_org` unless one is already running (an advisory lock on the org). The task message carries ids only; mode and values are always read from the DB (RT1).
  - **`run_org`, in this order:**
    1. Load the effective policy (values and `enforce` after their dates) and the holds (active or released within the delay). An org hold ends the run as `skipped_hold`. An enforce run with no effective `enforce` is downgraded to dry-run and audited.
    2. Sync the S3 legal holds of the case holds (`sync_holds`, bounded per run).
    3. For each category, select, then:
       - dry-run: write counts, sample and items for objects;
       - enforce: purge in batches (≤ `RETENTION_BATCH_ROWS` 5 000 rows or `RETENTION_BATCH_OBJECTS` 200 objects per transaction).
  - **Evidence:**
    1. Re-check under the tenant session that there is no hold, the case is still closed and there is no tombstone.
    2. `GetObjectRetention` and `GetObjectLegalHold` with the purge user. If the retention is in the future or the legal hold is ON → item `skipped_locked` / `skipped_hold`.
    3. Otherwise **commit** the `evidence_purges` tombstone + custody event `purged` (actor: `RETENTION_SYSTEM_USER_ID`, the inactive system user seeded by 0014, RT12; details: run id, version id) + audit `evidence.purged`.
    4. Then `DeleteObjectVersion`. A failure → item `object_delete_failed`; the next run retries objects whose tombstone exists and whose version is still present, including those left by a crash between 3 and 4 (no item, RT22).
  - **Results objects and renders:** the same tombstone-first idea, with a run item and `report_renders.status = purged` (allowed only for this role by the trigger), then the delete. A render can be requested again later and re-renders from the snapshot (0014 freed the unique index slot, RT11). A render still inside its GOVERNANCE retention is `skipped_locked`.
  - **Bulk rows, TI and AI:** `DELETE … WHERE id = ANY(:batch)` in the tenant session. One item per job and table with a row count.
  - **`job_outcomes`:** rows older than 90 days, deleted platform-wide once per sweep.
  - **Finish:** `retention_runs` status `succeeded | partial | failed` with counts; audit `retention.run_completed` (counts only).
  - **Time slicing:** stop after `RETENTION_RUN_SLICE_S` (300 s) and requeue `run_org` with the same run id.
- **Download and verify after a purge** (`evidence/transfer.py`): `410 evidence_purged` with `{purged_at, run_id}`. `EvidenceOut.purged_at` is set from the tombstone. The case evidence list shows it, and analyses on purged evidence are refused (`410`).

## Implementation Steps
1. `policy.py` (effective values, `enforce` and the delay) and the policy routes; `test_retention_policy.py`: floors, delay, raise immediate, enforce acknowledgement **and enforce delay**, the `retention_policy_index` upsert, audit, viewer 403.
2. `holds.py`, the hold routes and the `sync_holds` worker path (`objects.py`); `test_retention_holds.py` and `test_retention_objects.py` (test buckets: the legal hold is ON after a case hold and a sync, still ON and still protecting during the delay after release, OFF after it, stays ON while an org or other case hold covers; the purge user cannot delete a legal-held version or `*/snapshot.json`; the api user cannot delete in `reports` and has no legal-hold action).
3. `select.py`; `test_retention_select.py` (pure rules) and `test_retention_preview.py`:
   - the seeded aged case is selected and a reopened one is not;
   - held cases are excluded, and so are cases whose hold was released less than the delay ago;
   - cited AI, TI and bulk rows are kept;
   - a TI result reused by a recent `cached` run item is kept; an AI run tree with one recent or cited member is kept whole;
   - a case with no status event or with a running job is not selected;
   - the counts are deterministic.
4. The worker purge paths; `test_retention_purge.py` (in-process with `retention_session()` and the purge MinIO keys):
   - **dry-run ≡ enforce:** the dry-run set equals the purged set on the same seed and `now`;
   - tombstone, custody, audit and items are written;
   - the object version is gone and evidence answers 410;
   - the hashes, custody (actor: the system user), findings, IOCs, correlation keys, snapshot and audit remain;
   - a purged render re-renders;
   - an attempted manual enforce run before `enforce_effective_at` runs as dry-run;
   - the sweep finds the seeded orgs through `retention_policy_index`;
   - a delete failure (an injected MinIO error) is retried by the next run;
   - a GOVERNANCE-locked version is skipped.
5. `test_retention_append_only_exception.py`:
   - `cyberlab_retention` can DELETE `ti_results` and `ai_outputs` but not `audit_logs`, `evidence_hashes`, custody, `report_versions` or note versions;
   - no role can UPDATE the exception tables;
   - the app role cannot DELETE anything.
6. The runs routes and the manual run, plus time slicing; `test_retention_runs.py`.
7. `idor_cases_retention.py` with an empty `PENDING_ROUTES`, and the `reconcile_orphans` tombstone awareness test.

## Success Criteria
- [ ] With no policy, nothing is selected or purged.
- [ ] Lowered values, turning `enforce` on and hold releases wait for the delay, and floors and the destruction acknowledgement are enforced and audited.
- [ ] The dry-run equals enforce on the same seed. Enforce purges only expired, unheld, uncited candidates, tombstone first, with custody, audit and run items. Purged evidence answers 410 while its hashes and custody stay.
- [ ] Case and org holds exclude data at the DB level, and case holds also at the S3 level (synced by the worker; the api has no S3 hold action). The purge user can never delete a snapshot, a locked version or a legal-held version.
- [ ] TI and AI purges respect `ti_run_items` and run trees without FK errors; correlation keys survive.
- [ ] The append-only exception allows DELETE only for `cyberlab_retention` on the five tables, and the strict tables stay immutable.
- [ ] IDOR cases are complete and the lane passes.

## Risk Assessment
- **Destructive bugs.** Every delete path is gated by the selector and re-checked in the purge transaction, and the dry-run ≡ enforce test is mandatory. The default is dry-run.
- **FK order** when deleting AI runs (children, then `ai_run_index`, then the run) and bulk rows referenced elsewhere. Phase 1's grants list exactly what may be deleted, and an FK error fails the batch (it is rolled back) and is recorded.
- **S3 legal hold on many objects:** bounded per task plus the sync in runs. An org hold avoids S3 calls by design. Residual: a compromised retention worker could clear a hold and then delete (recorded in THREAT_MODEL, RT5).
- **Clock and `retain_until`:** always ask MinIO at purge time, never the DB's estimate.
