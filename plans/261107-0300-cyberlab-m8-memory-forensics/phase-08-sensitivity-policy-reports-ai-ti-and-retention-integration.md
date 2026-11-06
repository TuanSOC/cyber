---
phase: 8
title: "Sensitivity policy reports AI TI and retention integration"
status: pending
priority: P2
effort: "17h"
dependencies: [1]
---

# Phase 8: Sensitivity policy, reports, AI / TI and retention integration (group B, 2g, lane 8)

## Overview
A memory image holds whatever the machine held: passwords and hashes, session tokens, private keys, mail, documents, chat. M8 treats it as **TLP:RED material by default** (plan "Sensitivity"):
- a `kind=memory` upload (phase 6 calls the default in the upload transaction; RT3), or else the first memory job on an evidence item, marks it `restricted` and sets its M6 share policy to "do not send to AI" and "do not send to TI";
- only an org admin can **release** it, with an acknowledgement and a reason, audited; only then can the share-policy flags be cleared through the existing M6 route;
- a report includes memory-derived rows of restricted evidence only at TLP:RED;
- retention treats the memory tables as bulk derived rows (M7 `closed_case_days`).

Correlation inside the org is allowed (it never leaves the org and holds keys, not content).

**Owns:**
- `app/modules/memory_analysis/sensitivity.py` (the phase-1 stub `apply_memory_default` and the release service);
- the routes `GET /evidence/{id}/memory-sensitivity` and `POST /evidence/{id}/memory-sensitivity/release` in `memory_analysis/router_sensitivity.py` (a separate router file, so phase 7's `router.py` stays disjoint);
- the guard in `evidence/share_policy.py` (no clearing of a flag while restricted);
- the TLP guard in `reports/snapshot_sections.py` (memory-derived rows of restricted evidence) and the omitted count in `ReportSnapshot.omissions` (the field is added by phase 1; RT10);
- the omissions line in the report renderers `apps/workers/report/report_worker/render_md.py` and `render_html.py` (and their tests);
- the memory arm of `ai/context/builder.py:_digest_selections` (the phase-1 stub; a memory job's digest is its findings and IOCs only, never the pcap summary; RT1);
- `tests/security/idor_cases_memory_sensitivity.py` (the two sensitivity routes; RT24);
- `retention/select.py` (`BULK_TABLES` gains the four memory tables);
- `correlation/indexer.py` and `ai/context/select.py` **only if** a test shows they filter by analyzer (one-line additions; otherwise untouched; the red team found no analyzer filter in the indexer);
- `tests/integration/test_memory_sensitivity.py`, `test_memory_share_policy_guard.py`, `test_memory_reports_tlp.py`, `test_memory_ai_ti_policy.py`, `test_memory_retention.py`, `test_memory_correlation.py`.

## Requirements
- **Default** (`apply_memory_default(session, org_id, evidence_id, actor_id) -> bool`, called by phase 6 in the `kind=memory` upload transaction and in the job-creation transaction):
  - When `memory_sensitivity` has no row for the evidence: insert `state = restricted`, and upsert `evidence_share_policies` with `ai_excluded = true`, `ti_excluded = true` (never loosening an existing row). Audit `memory.sensitivity_defaulted`. Returns true when it changed something.
  - Idempotent: later memory jobs on the same evidence change nothing, and a `released` row stays released.
- **Release** (`POST …/memory-sensitivity/release`, `org.update`; body `{acknowledge_sensitive_content: true, reason}` with reason 10–500 characters):
  - `restricted → released` once (a trigger refuses any other transition; release is not reversible through the API, but an admin can set the share-policy flags again at any time).
  - It does **not** clear the share-policy flags itself: the analyst then uses the M6 `PUT …/share-policy` route as usual. Two explicit steps, both audited (`memory.sensitivity_released`, `evidence.share_policy_updated`).
  - `422 acknowledgement_required` without the flag; `409 memory_sensitivity_released` when already released.
- **Share-policy guard** (`evidence/share_policy.py`): while the evidence is `restricted`, a PUT that clears `ai_excluded` or `ti_excluded` answers `409 memory_sensitivity_restricted`. Setting flags is always allowed.
- **AI:** the M6 context builder skips AI-excluded evidence and the analyst worker re-checks before every provider request; the only AI code change is the memory arm of `_digest_selections` (findings + IOCs; no memory-specific task, RT1). Tests prove a memory job is `409 policy_blocked` by default, an incident summary skips it (`context_stats.policy_excluded`), and after release + PUT the memory findings (with masked secrets, phase 3) enter the context.
- **TI:** job-scope enrichment of a memory job answers `409 policy_blocked` by default (M6 path). Manual lookups carry no case scope (the M6 documented residual): the memory job page offers no "Enrich" button while restricted (phase 9).
- **Reports** (M6 snapshot builder): rows derived from a memory job whose evidence is `restricted` (its findings, IOCs, timeline entries and the job row's memory summary) are included only when the report's TLP is `red`. Otherwise they are left out and the snapshot sets `omissions = Omissions(memory_restricted=n)` (no limitations field existed; the parent accepted this additive field, which phase 1 adds with the canonical-bytes golden test; RT10). `omissions` stays `None` when nothing was left out, so reports without memory evidence keep byte-identical snapshots. The Markdown and HTML renderers print "N memory items omitted (restricted evidence; TLP:RED required)" under the findings section; the PDF follows the HTML. `409 memory_requires_tlp_red` is not needed (phase 1 no longer adds it).
- **Retention:** `memory_processes`, `memory_connections`, `memory_injections` and `memory_artifacts` join `BULK_TABLES` (purged for closed cases after `closed_case_days`, cited rows kept as `kept_cited`). `memory_images`, `memory_sensitivity`, findings and IOCs are never purged (the M7 rule). The memory image bytes are evidence bytes and follow the M7 evidence purge.
- **Correlation:** memory IOCs (external and internal IPs from connections, domains and URLs from command lines) are `iocs` rows, so the M7 indexer picks them up. A test proves a remote IP seen in a memory job and a pcap job of another case shows in "also seen in", with the memory job's link going to `/memory/{job}` (the phase-1 analyzer sweep).

## Implementation Steps
1. Read `investigations/policy.py`, `evidence/share_policy.py`, the M6 report snapshot schema (`cyberlab_jobs/report.py`, `snapshot_sections.py`), `retention/select.py`, `correlation/indexer.py`.
2. `sensitivity.py` and its router; the release trigger exists from phase 1.
3. The share-policy guard.
4. The report guard, the `omissions` count and the renderer lines; the AI digest arm.
5. `BULK_TABLES`; the purge test on a seeded aged closed case with a memory job.
6. AI, TI and correlation tests (no code change unless a test proves a filter).
7. Lane 8: `scripts/lane-test.sh 8 uv run pytest -q -p no:cacheprovider <own paths>`, `ruff`, `mypy`.

## Success Criteria
- [ ] The first memory job marks the evidence restricted and AI / TI excluded; later jobs change nothing.
- [ ] Clearing a flag on restricted evidence is refused; release needs `org.update` and the acknowledgement, happens once and is audited.
- [ ] AI runs and job-scope TI on a restricted memory job are `policy_blocked`; after release + PUT they proceed.
- [ ] A TLP:AMBER report leaves restricted memory rows out (with `omissions.memory_restricted` and the rendered line) and a TLP:RED report includes them; a report without memory evidence has `omissions = None`.
- [ ] A `kind=memory` upload is restricted before any job exists.
- [ ] A closed-case purge deletes the memory bulk rows and keeps images, findings, IOCs and cited rows.
- [ ] A memory IOC correlates with a pcap IOC of another case in the same org, never across orgs.

## Risk Assessment
- **Defaults that annoy analysts:** the restriction blocks the AI "explain" flow on memory jobs until an admin releases it. Intended (`requirement.txt` §9 and §13; legal exposure of memory contents). The UI explains why and who can release.
- **Report schema dependency:** resolved by the parent decision (additive `omissions`, RT10); never a silent omission. The report-worker image must be rebuilt with the new py-jobs (phase 1 does it).
- **Residual:** a user with `evidence.read` sees every command line and the injected-code heads of the job. Memory content is visible to every org member who can read the case (org-wide RBAC, M1). Recorded in THREAT_MODEL.
