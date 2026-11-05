---
phase: 10
title: "Docs threat model and audit quick wins"
status: pending
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
- [ ] Every audit quick win (1–9) and every listed overclaim is fixed or recorded as already fixed.
- [ ] The §11 mapping and the OpenSearch decision are documented, and the correlation module is described.
- [ ] DEPLOYMENT has tested-as-written backup, restore and retention runbooks and every new secret. THREAT_MODEL has the M7 section and the updated known gaps.
- [ ] ROADMAP, PRD, TESTING and README describe the current scope without overclaims.

## Risk Assessment
- **The runbooks drift from the scripts:** phase 11 runs the restore runbook commands as written during the drill review.
- **Doc size:** keep the M7 additions concise and link REPORTS / SANDBOX_SECURITY instead of duplicating them.
