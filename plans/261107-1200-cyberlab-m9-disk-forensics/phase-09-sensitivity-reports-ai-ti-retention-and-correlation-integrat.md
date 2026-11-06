---
phase: 9
title: "Sensitivity reports AI TI retention and correlation integration"
status: pending
priority: P2
effort: "13h"
dependencies: [1]
---

# Phase 9: Sensitivity, reports, AI / TI, retention and correlation integration (group B, 2g, lane 8)

## Overview
A disk image holds whatever the machine held. M9 treats it as **TLP:RED material by default**, through M8's sensitivity table extended by phase 1 (`memory_sensitivity` + `source`, `apply_restricted_default`, the generic release route, the share-policy guard; no rename, RT2). This phase wires the disk-specific consequences:
- the batch release of a disk job's segments (RT20);
- report omissions (`omissions.disk_restricted`) and the renderer line;
- the disk arm of the AI digest;
- the AI / TI policy proofs;
- retention of the bulk disk tables and the deletion of expired export objects (RT19);
- in-org correlation of disk IOCs.

The upload-time and job-time defaults are called by phase 7, and derived evidence by phase 10; this phase proves their end state.

**Owns:**
- the disk guard in `reports/snapshot_sections.py` and the `disk_restricted` count;
- the omissions line in `apps/workers/report/report_worker/render_md.py` and `render_html.py` (and their tests);
- the disk arm of `ai/context/builder.py:_digest_selections` (the phase-1 stub);
- `retention/select.py` (`BULK_TABLES` gains `disk_files`, `disk_events`);
- the export-object arm of `app/workers/retention.py` (the purge user deletes `expired` export versions; RT19);
- the batch-release arm (`job_id`) of `evidence/sensitivity.py` (the phase-1 stub; RT20);
- `correlation/indexer.py` and `ai/context/select.py` **only if** a test shows an analyzer filter (one-line additions; otherwise untouched);
- `tests/integration/test_disk_{sensitivity,batch_release,share_policy_guard,reports_tlp,ai_ti_policy,retention,export_purge,correlation}.py`.

## Requirements
- **Default (proved here, called elsewhere):**
  - `kind=disk` upload → `restricted` (source `disk`), `ai_excluded = ti_excluded = true`, never loosening;
  - the first disk job → the same on every segment;
  - derived evidence → `restricted` (source `derived`) when any source segment is restricted, plus the source's flags (phase 10 calls it in the promote transaction);
  - a `released` row stays released (idempotent).
- **Release** (phase 1's generic route over M8's `release`): `org.update`, `{acknowledge_sensitive_content: true, reason}` (10–500 characters), once, audited (`disk.sensitivity_released` for the `disk` / `derived` sources; M8's `memory.sensitivity_released` unchanged). The analyst then clears the flags through the M6 share-policy route. A released **source** does not release derived evidence: each item is released on its own (a recorded decision: an exported file can be more sensitive than its image's listing).
- **Batch release** (RT20): the body may add `job_id` of a disk `triage` / `full` job whose segments include the path evidence; every still-restricted segment of that job is released in the same transaction with the one acknowledgement and reason, one audit row per item, `409` if none is left; derived evidence is never included; a job of another investigation or org is `404`.
- **Share-policy guard:** clearing a flag on restricted evidence → `409 evidence_sensitivity_restricted` for the `disk` / `derived` sources (M8's `memory_sensitivity_restricted` for `memory`; phase 1); tests here cover the disk and derived sources.
- **AI:**
  - the context builder skips AI-excluded evidence; the analyst worker re-checks;
  - the disk arm of `_digest_selections`: findings + IOCs only (never file listings or events; no disk-specific AI task; `JOB_TASKS.disk = []`).
  - Tests: an AI run on a disk job is `409 policy_blocked` by default; an incident summary skips it (`context_stats.policy_excluded`); after release + PUT, the disk findings (with masked secrets) enter the context.
- **TI:** job-scope enrichment of a disk job → `409 policy_blocked` while restricted (M6 path); the job page hides "Enrich" (phase 11, via `enrichDisabledReason`). Hashes are never auto-submitted anywhere.
- **Reports** (M6 snapshot builder): rows derived from a disk job whose evidence (any segment) is restricted are included only at TLP:RED. Those rows are its findings, IOCs, timeline entries and the job summary. Otherwise they are omitted and counted into `omissions.disk_restricted`. `omissions` stays `None` when nothing was omitted, so other reports keep byte-identical snapshots. The Markdown and HTML renderers print "N disk items omitted (restricted evidence; TLP:RED required)" next to the memory line; the PDF follows the HTML. Derived-evidence static jobs follow the same rule through their evidence's state.
- **Retention:** `disk_files` and `disk_events` join `BULK_TABLES` (purged for closed cases after `closed_case_days`, cited rows kept as `kept_cited`). These are never purged by retention (the M7 rule): `disk_images`, `disk_partitions`, `disk_exports`, `analysis_job_segments`, `memory_sensitivity`, findings and IOCs. Segment bytes and exported objects:
  - segment bytes follow the M7 evidence purge;
  - unpromoted export objects: phase 10's beat task marks them `expired` after `DISK_EXPORT_TTL_S`; the **retention worker** (the only role with Delete on the results bucket: the `cyberlab-purge` user; the api user has Get / Put only, RT19) deletes each `expired` row's exact `object_version_id` and stamps `object_deleted_at`, retried on the next run when a delete fails; this runs whatever the retention mode (an expired export is never evidence);
  - promoted ones are evidence.
- **Correlation:** disk IOCs (hashes of flagged files, remote-logon source IPs, quoted URLs / domains) are `iocs` rows, so the M7 indexer picks them up. A test proves:
  - a sha256 seen in a disk job and as a static sample in another case shows "also seen in" both ways, with the disk link going to `/forensics/{job}`;
  - a disk job's correlation never reads another org.

## Implementation Steps
1. Read the generalized `evidence/sensitivity.py`, `investigations/policy.py`, the M6 / M8 report snapshot code (`snapshot_sections.py`, `Omissions`), `retention/select.py`, `correlation/indexer.py`, `ai/context/builder.py`.
2. The report guard, the count, the renderer lines (report-worker unit tests in its image, lane-free: the M8 precedent runs them in `report-worker-test` with one slot).
3. The AI digest arm; the AI / TI policy tests.
4. `BULK_TABLES`; a purge test on a seeded aged closed case with a disk job (files and events purged, findings kept, cited rows kept); the export-object purge test (an `expired` row's version deleted, `object_deleted_at` set, a `promoted` one untouched).
5. The batch release and its tests.
6. The correlation test (no code change unless a test proves a filter).
7. Lane 8, `ruff`, `mypy`.

## Success Criteria
- [ ] Every default path ends restricted and AI / TI excluded; derived evidence inherits; release is per item (or per disk job's segment set in one request), admin-only, acknowledged, once and audited.
- [ ] AI runs and job-scope TI on restricted disk jobs are `policy_blocked`; after release + PUT they proceed with masked findings only.
- [ ] Reports below TLP:RED omit restricted disk rows and print the count; reports without disk evidence keep byte-identical snapshots.
- [ ] Retention purges only `disk_files` / `disk_events` of eligible jobs, keeping cited rows, and deletes the object versions of expired exports.
- [ ] Disk IOCs correlate inside the org and never across orgs.

## Risk Assessment
- **Report snapshot compatibility:** covered by phase 1's golden test; the renderers are rebuilt with the api (plan merge step 5).
- **Over-restriction of derived evidence** (a known-good DLL exported from a restricted image stays restricted): intentional; release is one audited step.
