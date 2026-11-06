---
phase: 10
title: "Docs threat model and audit quick wins"
status: completed
priority: P1
effort: "8h"
dependencies: [2, 3, 4, 5, 6, 7, 8, 9]
---

# Phase 10: Docs, threat model and audit quick wins (group C)

## Overview
Document M7, close the documentation gaps and overclaims from `plans/reports/requirements-coverage-261106.md`, and reconcile the docs with the merged code. `docs/SANDBOX_SECURITY.md` was written by phase 7; this phase links it and checks it against the final code. **Re-check every quick win against the current files before editing**: M6 phase 9 or the group-B merge may already have fixed some.

**Owns:**
- `docs/{ARCHITECTURE,DATABASE,API,DEPLOYMENT,THREAT_MODEL,TESTING,ROADMAP,PRD,PCAP_ANALYSIS,THREAT_INTEL,AI_ANALYST,REPORTS}.md` (M7 sections and the fixes);
- `README.md`;
- the removal of the empty stray directory `scripts;C/` at the repo root.

## Requirements
- **ARCHITECTURE:**
  - the M7 components (retention-worker, db-bootstrap, the correlation indexer, the metrics path) in the network table and a diagram;
  - the `correlation` module (where it lives, deterministic, in-org) and the earlier AI-mediated correlation;
  - the **OpenSearch decision** (deferred, with the revisit criteria from plan.md and the phase-4 perf numbers);
  - the backup model (offline, volume-level MinIO and why).
- **DATABASE:**
  - the 0014 tables, grants, triggers, the retention role and the append-only exception;
  - the **§11 name → implementation mapping**:
    - `analysis_results` → the per-type result tables + `analysis_jobs.summary` + the `results` objects;
    - `threat_intelligence` → `ti_results` (+ runs, items, configs);
    - `attack_techniques` → the pinned JSON index + `case_attack_mappings`;
    - `investigation_timeline` → `analysis_timeline` + the merged computed timeline;
    - `api_keys` → the sealed provider keys (`ti_provider_configs`, `ai_provider_configs`); platform API keys are not implemented ("Later");
    - `forensic_artifacts`, `memory_findings` → deferred with their modules;
    - `malware_findings` → `analysis_findings` (already documented).
- **API:** the new routes, the `410 evidence_purged`, the rate-limit behaviour and the internal metrics endpoint (operators).
- **DEPLOYMENT:**
  - the **backup and restore runbook**: commands, the drain and maintenance window, what a backup contains (TLP:RED, RT6) and where to keep it (AV-excluded, encrypted), the secrets checklist, the age encryption example, the restore steps with the three verify phases, session revocation, `JWT_SECRET` rotation after an incident (RT26), and re-running retention after an older restore;
  - the restore drill;
  - retention operations (policies, the delay on lowering, on `enforce` and on hold release, holds and the worker-side S3 sync, the purge user, the system user, reading run items);
  - `db-bootstrap` and the new secrets (`POSTGRES_RETENTION_PASSWORD`, `BROKER_RETENTION_PASSWORD`, the purge MinIO keys, the KMS key, the metrics token);
  - SSE-S3 (new objects only; key loss also makes MinIO's IAM and config unreadable, RT7; the manifest key fingerprint);
  - the object-store image path (the decision from phase 6 and the switch procedure);
  - the Prometheus scrape config example;
  - the replacement of the M6 "Backups" paragraph.
- **THREAT_MODEL:** an M7 section with new assets and trust boundaries (retention worker, purge user, backups as an asset, the metrics endpoint), STRIDE notes, and the residuals:
  - backups hold everything (no plaintext secret, but all evidence and hashes) unless encrypted by the operator;
  - the KMS key is on the host;
  - query text is not logged and never in a URL;
  - S3 legal hold sync windows;
  - the api's M1 evidence delete grant can delete a version once its lock expires, without a tombstone (RT5); a compromised retention worker can clear an S3 hold, then delete;
  - no anonymous or gateway-level flood limit (RT14);
  - the object-store image decision.

  Close or update the M1 known gaps: no backups → closed (offline); metadata and custody views not logged → closed (deduplicated audit); MinIO frozen image → per the phase-6 decision; no rate limit → global per-user limit (anonymous: residual).
- **TESTING** (audit quick win 3, plus M7):
  - row 85: IOC enrichment metric ✅ 0.978 (`plans/reports/ti-metric-261105.md`);
  - delete the stale row 72 "Parser vulnerabilities ⏳ (no parsers yet)", or rewrite it as Done with the fuzz-lite and isolation suites;
  - next to "HostileProvider 0 violations", add the ASR 0.290 figure (canary leaks detected, not prevented);
  - the M7 suites, heavy steps and metric tables (filled by phase 11);
  - the §13 / §14 coverage rows for retention, backup / restore, rate limiting, worker failure rate and latency.
- **ROADMAP:**
  - an M7 row (scope, deferrals);
  - "Later" gains Autopsy, platform API keys / service accounts, TCP stream reassembly and file carving, OpenSearch (with the criteria), and online backup / PITR;
  - "Gated" links SANDBOX_SECURITY.md;
  - the M2 / M3 precision and recall note says "synthetic dataset".
- **PRD:** retitle (no "Milestone 1"); rewrite the non-goals table to the current scope (ClamAV, CSP and Celery are done); add the M7 stories.
- **PCAP_ANALYSIS and README:**
  - TShark covers capture info and the protocol hierarchy only; flows are Zeek conn-level with no stream reassembly or file carving.
  - The README AI analyst text says no live model run is recorded (or links the live-run report if phase 5 ran it).
  - The PDF/A-3a claim notes "checked locally with veraPDF, not gated".
  - The README precision / recall claims say "synthetic".
- **Reconcile:** THREAT_INTEL and AI_ANALYST (retention of `ti_results` and `ai_*`; the delete exception), REPORTS (renditions purgeable, snapshots never; legal hold on snapshots).
- Remove `scripts;C/` (empty).

## Implementation Steps
1. Re-check each audit quick win and overclaim against the current files, and list which remain.
2. Write ARCHITECTURE, DATABASE (with the mapping) and API.
3. Write DEPLOYMENT (runbooks) and THREAT_MODEL.
4. Make the TESTING fixes, ROADMAP, PRD, PCAP_ANALYSIS and README.
5. Reconcile THREAT_INTEL, AI_ANALYST, REPORTS and SANDBOX_SECURITY with the code. Remove `scripts;C/`.

## Success Criteria
- [x] Every audit quick win (1–9) and every listed overclaim is fixed or recorded as already fixed. — Quick wins 1–6, 8 and 9 and every listed overclaim are fixed (9316433; see the notes). Quick win 7 is closed at the plan closure: `plans/reports/report-metric-261106.md` exists (floors met), and the M6 plan and phase files are `completed`. ROADMAP's M6 row still says the metric report is not written; that is a docs edit outside the plan files.
- [x] The §11 mapping and the OpenSearch decision are documented, and the correlation module is described. — `docs/DATABASE.md` §11 mapping table (`analysis_results`, `threat_intelligence`, `attack_techniques`, `investigation_timeline`, `api_keys`, `forensic_artifacts` / `memory_findings`, `malware_findings`); `docs/ARCHITECTURE.md` "Platform operations (M7)" → "Correlation", "Search", "OpenSearch decision" (deferred, with the revisit criteria) (9316433).
- [ ] DEPLOYMENT has tested-as-written backup, restore and retention runbooks and every new secret. THREAT_MODEL has the M7 section and the updated known gaps. — Written: DEPLOYMENT "Backup and restore (M7)" (what a backup is (TLP:RED), take, restore, drill), "SSE-S3 and the KMS key", "Object-store image", "Retention operations", the Prometheus scrape example, and the env table rows for every new secret; THREAT_MODEL "M7: platform operations" and the updated "Known gaps" (backups, view audit, rate limit, MinIO image) (9316433). **Left unticked:** backup and restore ran only through `pnpm restore:drill` (the scripts the runbook calls, 0 mismatches) and the MinIO switch's backup; nobody ran the runbook commands by hand as written, and the retention runbook was not run as written. The THREAT_MODEL part is met.
- [x] ROADMAP, PRD, TESTING and README describe the current scope without overclaims. — ROADMAP M7 row ("done, pending its gate"), "Later" additions and the "Gated" link; PRD retitled ("Product Requirements", current scope M1–M7) with "Non-goals (current scope)"; TESTING rows (0.978, the parser posture row, ASR 0.290, the M7 suites and §13 / §14 rows); README (synthetic, TShark, no live model run, veraPDF not gated) (9316433). The M7 metric tables stay for phase 11 (pending gate).

## Risk Assessment
- **The runbooks drift from the scripts:** phase 11 runs the restore runbook commands as written during the drill review.
- **Doc size:** keep the M7 additions concise and link REPORTS / SANDBOX_SECURITY instead of duplicating them.

## Implementation Notes (2026-11-07)
- **Commit:** 9316433 (phases 2–10 together). The docs were written against the merged group-B code.
- **Re-check first (step 1):** every quick win of `plans/reports/requirements-coverage-261106.md` was checked against the current files:
  - quick win 2 was already done by phase 7 (`SANDBOX_SECURITY.md`, now linked);
  - the M5 part of quick win 7 was already done (`plan.md` is `completed`);
  - `scripts;C/` is gone from the repo root (quick win 8).
- **Quick wins fixed:**
  - 1: the DATABASE §11 table;
  - 3: TESTING shows the IOC enrichment ✅ 0.978 (synthetic faults), the parser row rewritten as a posture row (isolation + fuzz-lite) and ASR **0.290** next to "0 floor violations";
  - 4: the PRD title and non-goals;
  - 5: ROADMAP "Later" gains Autopsy, platform API keys / service accounts, TCP stream reassembly / file carving, OpenSearch with criteria, and online backup / PITR;
  - 6: the ARCHITECTURE OpenSearch decision and the correlation module;
  - 9: PCAP_ANALYSIS (TShark covers the protocol hierarchy only; flows are Zeek conn-level).
- **Overclaims fixed:**
  - ROADMAP M6 notes the missing gate metric report;
  - README: PDF/A-3a "veraPDF runs locally only and does not gate", "No live model run has been recorded", precision / recall "synthetic", TShark limited to the protocol hierarchy;
  - TESTING HostileProvider: detected, not prevented.
- **ARCHITECTURE "Platform operations (M7)":**
  - retention-worker, db-bootstrap, the indexer and the metrics path;
  - backup and restore (offline, volume-level MinIO and why);
  - retention, correlation and search, including **indexes vs RLS**: a per-org scan, accepted pending the perf numbers, with the 0015 options;
  - the OpenSearch decision, runtime metrics and security hardening.
- **DATABASE:** the 0014 tables, grants, triggers, the retention role, the append-only exception and the search indexes, with the note that RLS keeps them unused.
- **API:** the new routes, including `POST /correlations/lookup` (moved from GET by the security review), `410 evidence_purged`, the global rate limit (600 per minute, `/auth/me` exempt, 503 fail closed) and `/internal/metrics` for operators.
- **DEPLOYMENT:**
  - the upgrade note for an existing checkout (back up first, then the KMS key encrypts IAM from then on);
  - the M7 prod secrets and the env rows;
  - the backup / restore / drill runbook (TLP:RED contents, AV-excluded encrypted storage, the age example, the three verify phases, session revocation, the `JWT_SECRET` rotation after an incident (RT26));
  - **gap:** the optional manifest HMAC (`BACKUP_MANIFEST_KEY`, phase-2 review fix) is documented only in `scripts/backup.mjs` and `lib/stack.mjs`, not in DEPLOYMENT;
  - SSE-S3 and the KMS key, retention operations and the Prometheus scrape example.
- **KMS shared-volume caveat for `verify:prod`:** recorded in TESTING and DEPLOYMENT. Until phase 11 settles key sharing, run the prod gate on a fresh project (`COMPOSE_PROJECT_NAME=cyberlab-clean`).
- **Object-store image:** DEPLOYMENT and THREAT_MODEL say upstream was archived on **2026-04-25** and that the bitnami image is unpatched (CVE-2025-62506; SN-2026-015/016, a GOVERNANCE bypass). They give the **recommended `pgsty/silo` pinned by digest, pending the user's decision**, and the switch procedure (backup, conformance against the candidate, the drill with `--target-minio-image`, then `MINIO_IMAGE` / `MINIO_DATA_DIR=/data`).
- **THREAT_MODEL, M7 section and known gaps:**
  - residuals: backups hold everything, the KMS key is on the host, the query is never in a URL or a log, the S3 hold sync windows, the api delete grant (RT5), a compromised retention worker, no anonymous flood limit (RT14), search under RLS, and the MinIO image;
  - closed in M7: no backups (closed, offline) and metadata views not logged (closed, deduplicated audit);
  - updated: the rate limit (per user; the anonymous limit stays a residual);
  - still open: the MinIO image.
- **Reconciled:** THREAT_INTEL and AI_ANALYST (retention of `ti_results` / `ai_*` through the delete exception), REPORTS (renditions purgeable, snapshots never; legal hold on snapshots) and SANDBOX_SECURITY against the code.
- **Not done:**
  - quick win 7's M6 bookkeeping: the M6 phase statuses and `report-metric-*.md` are outside this phase's files;
  - the M7 metric tables in TESTING, filled by phase 11.
- **Pending gate:** running the runbooks as written (the phase-11 drill review), and the ROADMAP M7 row moving from "done, pending its gate".
- **Closure (2026-11-06):** The drill ran the backup and restore scripts, but the runbooks were not run by hand as written (criterion left unticked). ROADMAP's M7 row still says "done, pending its gate" (docs, outside the plan files).
