---
phase: 8
title: "Docs and threat model"
status: pending
priority: P1
effort: "6h"
dependencies: [2, 3, 4, 5, 6, 7]
---

# Phase 8: Docs and threat model (group C)

## Overview
Document M6 as built after the group-B merge: the new `docs/REPORTS.md`, plus the updates to every affected document. It may run while the parent fixes merge seams. Phase 9 reconciles the wording with the final gate facts.

**Owns:**
- `docs/REPORTS.md` (new);
- `docs/{ARCHITECTURE,DATABASE,API,THREAT_MODEL,AI_ANALYST,THREAT_INTEL,MALWARE_ANALYSIS,DEPLOYMENT,ROADMAP,PRD}.md`;
- `README.md`.

## Requirements
- **`docs/REPORTS.md`**, the reference for the milestone:
  - The model: draft vs immutable version, the finalize transaction, versions never deleted, discard only without versions.
  - The snapshot `cyberlab.report.v1`: sections, caps and totals, canonical JSON rules, size limit.
  - Citations: sources, `C` numbering, row copies with `fields_sha256`, deep links, "cited by".
  - The AI content rule: only supported claims and labelled hypotheses, plus the disclaimer.
  - The redaction profiles (`internal` / `external`): one report-level map, the field walk and its allow-list, the second whole-token pass, the external-review ack, and the residual (pseudonymization is pattern-based; the map is not stored) (RT2, RT8, RT29).
  - Finalize: the read / put-and-sign / write steps, the TLP re-check against the current case TLP, the change note and document control (RT7, RT14, RT23).
  - **Signing:** the Ed25519 manifest, kid rotation runbook (`gen_report_signing_keys.py --add`, set the active kid, old public keys kept forever for verification), the unauthenticated public-key route and how external recipients get the keys (RT22), `scripts/verify_report.py` usage with an example, and why PAdES is not used.
  - **Renderer:**
    - why WeasyPrint;
    - the isolation (network, seccomp socket deny, rlimits, deny-all fetcher, constant options, autoescape and the lint);
    - formats (PDF/A-3a with embedded snapshot, manifest and signature; HTML; Markdown; DOCX deferred, RT12);
    - the render budget (`render_units`, `report_too_large_to_render`) and the calibrated values (RT1);
    - reproducibility;
    - accessibility (tags, language, title, headings, table headers; veraPDF is a local check);
    - typed render errors and their hints;
    - "the signed snapshot is the record of truth".
  - **TLP 2.0:** labels, colours, the marking rule on every page and export, the downgrade rule, distribution for RED and AMBER+STRICT.
  - **Share policy:** flags on cases and evidence, TLP:RED implies both, where it is enforced (API and workers), who may turn flags off.
  - **Case management:** notes (versions, soft delete), IOC collections (normalization, exports with formula safety and STIX TLP marking), status reasons and history, ATT&CK case mapping and suggestions, timeline kinds and export.
  - Metrics (from phase 9) and limitations.
- **ARCHITECTURE:**
  - the report-worker in the service, network and trust diagrams;
  - the new modules (`notes`, `ioc_collections`, `case_attack`, `case_timeline`, `reports`);
  - the render pipeline (API → broker → report-worker → MinIO → ingest).
- **DATABASE:** the 0012 tables, triggers, grants, append-only list and indexes (`report_citations (org, kind, ref_id)` next to the M5 indexes).
- **API:** every new route with its permission, error codes and download headers.
- **THREAT_MODEL:** a new "M6: reports and case management" section. Its threat table:

  | Threat | Mitigation |
  |---|---|
  | Renderer RCE through parser bugs in untrusted text | isolation, seccomp, rlimits, re-hash |
  | SSRF and local-file read through the renderer | deny-all fetcher, constant options, the pinned CVE fixes |
  | HTML / CSS / Markdown injection | escaping, the lint, the escaper, the meta CSP on the HTML artifact |
  | CSV formula injection | `csv_safe` (leading whitespace and full-width forms included) |
  | STIX pattern injection | escaping |
  | Unrenderable or resource-exhausting reports | render budget at finalize, page and size caps, rlimits |
  | Pseudonym collisions and leaks in external reports | one report-level map, field walk, second pass, review ack |
  | Forged or altered reports | Ed25519 manifest, object lock, append-only, verify on read |
  | TLP downgrade and over-sharing | the downgrade rule, distribution, the `external` profile |
  | Policy bypass for AI and TI | API checks plus worker re-checks |
  | IDOR across new routes | the enumerator |
  | Report download leakage | audit, attachment, CSP sandbox, no presigned user URLs |

  - **Residuals:**
    - a misleading PDF from a compromised renderer;
    - the API-held signing key;
    - pattern-based pseudonymization (and the unstored report map);
    - manual TI lookups are not case-scoped, and an in-flight provider call completes after a flag flips;
    - viewers (`evidence.read`) can download any report, TLP:RED included; downloads are audited (RT31);
    - no PAdES or timestamping;
    - veraPDF not in CI;
    - no retention.
  - Close the M4 RT26 and M5 "no TLP / do not send to AI" residual rows by pointing to the new controls.
- **AI_ANALYST:** the share-policy refusals (`409 policy_blocked`, `failed / policy_blocked`), the incident skip with its `policy_excluded` stat, and reports embedding verified outputs.
- **THREAT_INTEL:** enrichment refused by policy and TLP:RED, and IOC collections joining `ti_results` by `ioc_key`.
- **MALWARE_ANALYSIS:** the static JSON report stays as the job-level export, and case reports are in REPORTS.md.
- **DEPLOYMENT:**
  - the `reports` and `reports-test` buckets (object lock, no default retention, per-object retention, no delete in the policy);
  - the report-worker service, image, limits, prod overlay and scaling (one render per replica; the global cap is per replica);
  - `BROKER_REPORT_PASSWORD`;
  - the signing keys (prod generation, secret file, rotation) and the published public keys;
  - `PUBLIC_BASE_URL`;
  - backup notes: the bucket and DB rows must be backed up together.
- **ROADMAP:** M6 ✅ row with its deferrals (DOCX, PAdES, timestamps, KMS, templates per org, images and charts, sharing, approvals, TAXII / MISP push, org-wide watchlists, retention, veraPDF in CI, per-case access control). Remove "analyst notes, IOC collections" from "Later".
- **PRD:** the reporting and case-management user stories.
- **README:** the feature list and the quick start for reports.

## Implementation Steps
1. Read the merged code and the phase notes, and draft REPORTS.md.
2. Update ARCHITECTURE, DATABASE and API from the code (route list from `packages/contracts/openapi.json`).
3. THREAT_MODEL section and residual closures; AI_ANALYST, THREAT_INTEL and MALWARE_ANALYSIS notes.
4. DEPLOYMENT, ROADMAP, PRD and README.
5. Cross-link the docs and check every referenced test name exists (grep).

## Success Criteria
- [x] REPORTS.md documents the model, the snapshot, citations, signing with the verify runbook, the renderer isolation, TLP and the share policy, and case management, all matching the code. — `docs/REPORTS.md` (319f04d, +246) has the sections Case management (notes, IOC collections, status, ATT&CK, timeline), TLP 2.0, Share policy, Reports (draft and versions, finalize, snapshot, citations, AI content, redaction profiles), Signing (key rotation, offline verification with a `verify_report.py` example), Renderer (why WeasyPrint, isolation, formats, render budget and caps, accessibility), Metrics and Limitations. It was reconciled with the phase-9 fixes in e6e0665. The independent reviewer pass over the docs is still open (phase 9).
- [x] THREAT_MODEL has the M6 section with tests cited per threat, and the old TLP and AI residual rows point to their controls. — `docs/THREAT_MODEL.md` "M6: reports and case management": 16 threats with a "Tested by" column and a residual table. The M4 TI / TLP row and the M5 "do not send to AI" row now say "**closed in M6:**" with the controls (319f04d, e6e0665).
- [x] DEPLOYMENT covers the bucket, worker, keys and broker password. ROADMAP marks M6 and lists its deferrals. — `docs/DEPLOYMENT.md` "Reports (M6)": buckets, report-worker, signing keys with the review-L3 startup check, published public keys, `PUBLIC_BASE_URL`, backups; the env table rows `BROKER_REPORT_PASSWORD`, `REPORTS_BUCKET` / `REPORTS_TEST_BUCKET`; the M6 upgrade steps. `docs/ROADMAP.md` has the M6 ✅ row with its deferrals (DOCX, the "Cited by" panel, …), and analyst notes / IOC collections are gone from "Later" (319f04d).
- [x] Every test name cited in the docs exists. — checked 2026-11-06 by grep: every distinct `test_*` name in `docs/REPORTS.md`, the THREAT_MODEL M6 section and the M6 part of `docs/TESTING.md` (258 names) resolves to a test function or test file under `apps/` or `packages/`. The only non-match, `test_version`, is a substring of `latest_version`.

## Risk Assessment
- **Docs written before the gate** can drift. Phase 9 reconciles the wording and the numbers.

## Implementation Notes (2026-11-06)
- **Commits:**
  - 319f04d: the docs as group C, after the group-B code was in the main tree. Phases 2–8 landed as one commit.
  - e6e0665: the phase-9 reconciliation of ARCHITECTURE, DATABASE, DEPLOYMENT, REPORTS, ROADMAP, TESTING and THREAT_MODEL (+27 / −23).
- **Files (319f04d):**
  - `docs/REPORTS.md` (new, +246);
  - ARCHITECTURE (+56), DATABASE (+65), API (+51), DEPLOYMENT (+44), TESTING (+45), THREAT_MODEL (+45);
  - PRD (+14), ROADMAP (+10), AI_ANALYST (+10), THREAT_INTEL (+6), MALWARE_ANALYSIS (+2);
  - `README.md` (+21).
  - `docs/TESTING.md` (+45) is not in the owned list; it gained the M6 suites and the metric table in the same commit.
- **Written from the merged code**, including the review and integration fixes:
  - DATABASE documents `0013_m6_same_org_fks` (review L4);
  - DEPLOYMENT has the prod `check_startup_keys` (review L3);
  - REPORTS has the 450 000-unit budget and the uid-10004 / `AF_UNIX`-only sandbox (review L5 / L6);
  - REPORTS, AI_ANALYST, ARCHITECTURE and THREAT_MODEL state that analyst notes and status reasons never enter AI context.
- **Metrics recorded** in REPORTS.md and TESTING.md:
  - 450 000 units: worst 594 MiB RSS of 768 MiB, ≤ 214 pages (cap 300);
  - golden PDF p50 / p95 3.9 s;
  - deterministic PDF (`test_rendering_twice_gives_identical_bytes`);
  - hostile escapes 0;
  - veraPDF "local check only, not gating".
- **THREAT_MODEL:**
  - 16 threat rows with "Tested by", beyond the planned 12 (also fabricated citations, case-management text reaching a provider, history tampering, broker pivot);
  - the residuals (compromised renderer, API-held key RT26, pattern-based pseudonymization, in-flight calls, viewer downloads RT31, no PAdES / timestamps, veraPDF not in CI, no retention);
  - the M4 / M5 rows marked "closed in M6".
- **DEPLOYMENT:**
  - the object lock, no default retention and per-object GOVERNANCE retention, with no `DeleteObject*`;
  - the report-worker limits (1 GiB, 1 CPU, `pids_limit` 128, tmpfs `/tmp` 16 MiB and `/work` 96 MiB);
  - one render per replica (`REPORT_ACTIVE_RENDERS_GLOBAL` 4);
  - key generation and rotation (`gen_report_signing_keys.py --add`), and the published-keys table with `dev-report-1`;
  - backups of the bucket and the rows together, and `reconcile_orphans.py`.
- **Limitations documented:** DOCX deferred (RT12); no PAdES, RFC 3161 or KMS; no CJK glyphs in the PDF (`fonts-noto-core`).
- **Test-name check (step 5):** run again on 2026-11-06 over REPORTS.md, the THREAT_MODEL M6 section and the M6 part of TESTING.md. All 258 distinct names resolve.
- **Open (phase 9):**
  - the §14 metric run and `plans/reports/report-metric-*.md` (not written);
  - the veraPDF result (not run);
  - the reviewer pass;
  - the final numbers from `pnpm verify:prod` (pending gate).
