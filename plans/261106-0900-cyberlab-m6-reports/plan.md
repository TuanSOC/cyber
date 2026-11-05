---
title: "CyberLab M6 Reports and Case Management"
description: >-
  Professional, evidence-cited investigation reports and the remaining case management:
  analyst notes (versioned), IOC collections (CSV / JSON / STIX 2.1 export), status history,
  TLP 2.0 and "do not send to AI / TI" share policies enforced in the AI and TI paths,
  analyst-confirmed ATT&CK case mapping, and timeline export. A report draft is
  finalized into an immutable, signed snapshot (canonical JSON, sha256, Ed25519)
  with a citation appendix. An isolated, sandboxed WeasyPrint report-worker
  (no egress, no JS, no fetches, rlimits) renders it to PDF/A-3a, HTML and Markdown
  (DOCX deferred, RT12).
status: pending
priority: P1
effort: 113h
branch: "feat/m6-reports"
tags:
  - feature
  - reports
  - case-management
  - security
blockedBy: [261105-2100-cyberlab-m5-ai-analyst]
blocks: []
created: "2026-11-06T09:00:00.000Z"
createdBy: "ck:plan"
source: skill
---

# CyberLab M6 Reports and Case Management

## Overview

**Requirements this milestone covers:**
- `requirement.txt` §1: "generate professional reports".
- §2: MVP item 6, "Investigation Reporting".
- §9: "generate reports with evidence citations".
- §10 asks case management to support evidence, custody, jobs, findings, **IOC collections**, **analyst notes**, timeline, **ATT&CK mapping**, **case status** and **report generation**, and to "preserve original evidence and analysis history".
- §11 lists `analyst_notes`, `reports` and `attack_techniques` tables.
- §14 asks for measured quality.

**Deferred items M6 picks up:**
- ROADMAP M3: a persisted `reports` table.
- ROADMAP M4 and M5, plus THREAT_MODEL RT26: a TLP model and a "do not send to AI" flag on evidence and cases.
- ROADMAP M5: reports embed `ai_outputs`, and "which outputs cite this row" is answered through `ai_citations` / `ai_context_refs`. Their indexes on (org, kind, ref_id) already exist.

**What exists today (scout, 2026-11-06):**
- **Case status workflow:** `investigations.status` (`open`, `in_progress`, `closed`, `archived`) with `TRANSITIONS` in `investigations/service.py`. M6 adds a reason and a history, not a new workflow.
- **Case timeline:** `GET …/investigations/{inv}/timeline` (`investigations/timeline.py`).
- **AI citation deep links:** `ai/service_outputs.py: deep_link`, `LinkContext`.
- **ATT&CK index:** v20 offline (`attack/index.py: label`, `get_index`).
- **On-demand static JSON report:** `static_analysis/report.py`, plus a `window.print()` page.
- **Missing:** no notes, IOC collections, TLP, signing utility, report bucket or PDF generation.

The plan builds on M5 (`feat/m5-ai-analyst`; its gate is still running).

**Inputs:**
- `plans/reports/researcher-261106-m6-report-rendering.md`: renderer choice, WeasyPrint hardening and CVEs, templating, DOCX / Markdown, signing, TLP 2.0, report structure, accessibility.
- The scout facts above, plus `docs/{ARCHITECTURE,THREAT_MODEL,AI_ANALYST,MALWARE_ANALYSIS,ROADMAP}.md`.

Decisions taken by the parent are marked **(decision)**. The red-team pass ran on 2026-11-06 (table below). Changed passages cite their RT id.

## Architecture (decided)

    analyst (UI) -> API (requester's require() session, RLS)
      case management: notes (append-only versions), IOC collections, status + reason (history),
        TLP + share policy (case: ai_excluded / ti_excluded; evidence: share-policy rows),
        ATT&CK case mappings (analyst-confirmed; suggestions from capa / findings / verified AI)
      report draft (mutable, optimistic revision) -> POST finalize
        -> snapshot builder (API, requester's session): case, analyst sections, evidence + trusted
           hashes, custody, jobs + tool versions, selected findings / alerts / IOCs / TI (attributed),
           ATT&CK mappings, timeline, notes (opt-in), AI runs (verified claims only), citations
           [C1..Cn] -> each cited row copied (bounded fields) + fields_sha256 + internal deep link
           (built in ONE read-only REPEATABLE READ transaction, RT14)
        -> redaction profile (internal | external: one report-level pseudonym map over every
           string field, AI runs re-mapped onto it; drop notes, deep links, custody IPs /
           user agents, analyst names; RT2, RT8)
        -> render budget check (RT1) -> canonical JSON (cyberlab.report.v1) -> sha256
        -> MinIO `reports` bucket (versioned, object lock, per-object GOVERNANCE retention;
           put OUTSIDE any DB transaction) -> Ed25519 signature over a manifest
        -> ONE short write transaction (advisory lock, re-check revision, latest_version and
           the TLP rule, RT7): report_versions + report_citations + report_renders(pdf, queued)
           + report_render_index + audit report.finalized -> commit -> send_task report.render
      -> report-worker (UNTRUSTED zone, own image, `analysis` network = broker + MinIO only,
         no egress, no DB, no secrets but its broker user)
         -> presigned GET snapshot, sha256 check -> sandboxed subprocess (uid 10003, seccomp
            denies AF_INET/AF_INET6/AF_NETLINK/AF_PACKET sockets and io_uring, RLIMIT_AS / CPU,
            empty env, tmpfs cwd)
            -> Jinja2 SandboxedEnvironment(autoescape, StrictUndefined) -> HTML
            -> WeasyPrint (deny-all URLFetcher, constant options) -> PDF/A-3a with the
               snapshot + manifest + signature embedded | HTML | Markdown
         -> size / magic / page checks -> presigned POST artifact -> report.rendered (ingest queue)
      -> ingest-worker (trusted): per-render token, org from report_render_index, artifact
         sha256 re-hashed from MinIO -> report_renders succeeded
      -> UI: React viewer renders the snapshot JSON (`GET …/versions/{v}/content`, RT11) as text
         (never the renderer's HTML),
         TLP banners, signature and hash status, citation appendix with deep links; downloads
         are streamed by the API, audited, attachment + CSP sandbox + nosniff

**Renderer (decision): WeasyPrint ≥ 70 in an analyzer-class worker. Not Chromium, Playwright, Gotenberg or `window.print`.**
- **Why WeasyPrint:**
  - It has no JS engine.
  - Every resource load goes through one choke point (`URLFetcher`), which we make deny-all.
  - It outputs native PDF/A-3a (tagged, with attachments) and can produce PDF/UA-1.
  - Output is reproducible with a fixed `pdf_identifier` and fixed dates.
  - It needs only Pango and HarfBuzz from Debian.
- **Why not Chromium:**
  - Its sandbox needs a user-namespace seccomp profile and `--ipc=host`. That conflicts with `cap_drop: [ALL]`, and `--no-sandbox` is the only alternative.
  - The image is 1–2 GB.
  - V8 and Blink ship CVEs monthly.
  - Output is not reproducible.
- **Why not Gotenberg:** it is the same Chromium plus an HTTP API with a 2026 history of SSRF deny-list bypasses.
- **Why not `window.print`:** output varies by browser, it cannot be signed or archived, and the TLP marking is not guaranteed. The existing static print page stays as a convenience.
- **Pin and options:**
  - Pin `weasyprint>=70.0,<71`. 70.0 fixes CVE-2026-55073 (the `stylesheets` / `xmp_metadata` arguments bypassed the fetcher) and CVE-2026-106443 (EPS images reached Ghostscript through Pillow: RCE), 69.0 fixes CVE-2026-49452 (presentational hints → CSS injection) and 68.0 fixes CVE-2025-68616 (redirect SSRF). Also `fonttools>=4.60.2` (CVE-2025-66034). Checked on PyPI / OSV / GHSA during the red-team pass (RT16); phase 1 re-checks before locking.
  - The image has no Ghostscript (RT16).
  - `write_pdf` options are constants and never derived from data. `presentational_hints=False`. In 70.0 `srgb` is `output_intent`, and every PDF/A variant forces it (RT17).

**Trust and isolation** (reuses the M2/M3 analyzer pattern; the renderer handles attacker-controlled text from captures, samples, TI, AI output and analyst input)
- **`report-worker`:**
  - Image: own image `apps/workers/report` (python:3.12-slim + `libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 libseccomp2` + `fonts-noto-core fonts-noto-mono`, no Ghostscript). Fontconfig points only at the bundled fonts.
  - Hardening, cloned from the static worker anchor: `init`, `read_only`, `cap_drop: [ALL]` plus the analyzers' `cap_add: [SETUID, SETGID, KILL, CHOWN, DAC_OVERRIDE, FOWNER]`, `no-new-privileges`, `pids_limit: 128`, `mem_limit: 1g`, `cpus: 1`, tmpfs `/tmp` (16 MiB) and a root-owned tmpfs `/work` (`size=96m,mode=0711`, `noexec`) for the snapshot, the HTML and the artifact (RT3, RT4).
  - The worker process runs as **root inside the container, as the analyzers do**, and drops the render subprocess to uid 10003. A non-root worker uid cannot `setuid` (RT3).
  - **Networks `[analysis]`** (internal: broker + MinIO only, no default route).
  - Env: only `BROKER_URL` (broker user `report`: `~report* ~test.report*`). No DB, JWT, MinIO credentials, signing key or app Redis.
  - Input and output only through presigned GET / POST URLs in the message, the M2 pattern. Celery **prefork `--concurrency 1 --max-tasks-per-child 1`**, the analyzers' command line, because the solo pool enforces neither the child recycling nor the hard time limit. Time limits soft 90 s / hard 120 s (RT4).
- **Render subprocess** (`py-worker-kit` sandbox, extended in phase 1, RT3):
  - uid 10003, empty env (plus `MALLOC_ARENA_MAX=2` so glibc arenas fit under `RLIMIT_AS`), cwd in the `/work` tmpfs, `RLIMIT_AS` 768 MiB, `RLIMIT_CPU` 90 s, `RLIMIT_FSIZE` = artifact cap, `RLIMIT_NOFILE` 64, `RLIMIT_NPROC` 16.
  - Seccomp (the worker-kit libseccomp filter, extended in phase 1) denies `socket(AF_INET | AF_INET6 | AF_NETLINK | AF_PACKET)` with `EACCES`, and `io_uring_setup` (its `IORING_OP_SOCKET` bypasses a `socket()` filter). The renderer has **no network at the syscall level** even though its parent can reach the broker.
  - Python `-I -B`: isolated mode (no `PYTHON*` env, no cwd or user site on `sys.path`) without `.pyc` writes. **Not `-S`**, which would drop the venv's site-packages and break every import (RT4).
- **Deny-all fetcher (decision, RT16):** a `URLFetcher` subclass whose `fetch` raises `FatalURLFetchingError` for **every** URL. WeasyPrint 70 sends `data:` (urllib `DataHandler`), `file:`, `http(s):`, `@import`, `@font-face url()` and attachments given as filenames through the fetcher, so nothing is allowed:
  - the CSS is a trusted constant passed as `CSS(string=…)`;
  - fonts come only from fontconfig (`local()`, the bundled Noto set), never `@font-face url()`;
  - attachments are passed as bytes;
  - `base_url=None`.

  Any URL fails the render closed. Templates never emit `<img>`, `<link>`, `@import` or `url()`.
- **Templates:**
  - `SandboxedEnvironment(autoescape=True, undefined=StrictUndefined)`, Jinja2 ≥ 3.1.6.
  - A CI lint bans `|safe`, `Markup(`, `{% autoescape false %}` and `style=` / `class=` built from data.
  - Severity and TLP map to fixed CSS classes.
  - Evidence-derived and AI text is **defanged by the snapshot builder** (the snapshot holds the defanged form, RT24); renderers and the viewer apply only the `vis` rule. Bidi / zero-width / control characters are made visible (`⟨U+202E⟩`) from a materialized range table (`vis_rules.json`, generated from the M5 `ai/text.py` categories, RT24). Analyst text is not defanged.
  - AI and analyst text is plain paragraphs, never Markdown or HTML.
  - The HTML artifact carries `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">`, because a downloaded file opened from disk gets no response header (RT19).
- **Output checks before upload:**
  - PDF: starts `%PDF-`, ≤ `REPORT_MAX_ARTIFACT_BYTES` (32 MiB), ≤ `REPORT_MAX_PAGES` (300, RT1).
  - Markdown / HTML: UTF-8 and ≤ the cap.
  - **The ingest-worker re-hashes the stored object.** A compromised renderer can produce a wrong rendition, but it cannot alter the signed snapshot, another tenant's data or any DB row.
- **The signed snapshot is the record of truth (decision):** renditions are views of it. The PDF embeds `snapshot.json`, `manifest.json` and `manifest.sig.json` (PDF/A-3 attachments) and prints the version and short sha256 on every page. `scripts/verify_report.py` checks a PDF or a snapshot offline against the published public keys.
- **No HTML from the renderer is shown in the app.** The viewer renders the snapshot JSON with React text nodes. Downloaded HTML is an attachment with `Content-Security-Policy: sandbox; default-src 'none'; style-src 'unsafe-inline'`, `nosniff` and `no-store`.

**Snapshot, versioning and signing** (decision)
- **Draft vs version:**
  - A `reports` row is a mutable **draft**: title, TLP, profile, analyst sections, selections and distribution. It carries an integer `revision` for optimistic concurrency (`409 stale_draft`).
  - `POST …/finalize` freezes the draft into **`report_versions` v(n+1), append-only**. The draft stays editable for the next edition, and versions are never deleted.
  - A draft without versions can be discarded (`status=discarded`).
- **Snapshot `cyberlab.report.v1`:** Pydantic models in `packages/py-jobs` (`cyberlab_jobs/report.py`), shared by the API and the renderer as the analyzer contracts are.
  - Canonical JSON: sorted keys, UTF-8, no insignificant whitespace, integers only, timestamps as RFC 3339 `Z`.
  - The snapshot's own sha256 is the version id on paper.
  - Caps:
    - findings 500, alerts 500, IOCs 2 000;
    - timeline 1 000, citations 2 000, AI runs 10, notes 200;
    - evidence-derived free text (`BoundedText`) ≤ 4 096 characters with `…[truncated n]`;
    - analyst-authored text (`AnalystText`: the draft sections, notes, rationale) ≤ 20 000 characters, never truncated, matching what the API accepts (RT9);
    - the whole snapshot ≤ `REPORT_MAX_SNAPSHOT_BYTES` (8 MiB) → `422 report_too_large` with the per-section counts.
  - **Render budget (RT1):** a signed version must be renderable, because versions are immutable. The contract computes `render_units(snapshot)` (rendered text characters plus a per-row weight). Finalize refuses `422 report_too_large_to_render` (with the per-section counts) above `REPORT_MAX_RENDER_UNITS`. Upstream reports roughly 2.6–3 GB for 1 500 pages (about 2 MB per page, because the whole document stays in memory), so the initial value targets about 250 A4 pages within the 768 MiB / 90 s sandbox. Phase 4 calibrates it on a worst-case-at-budget fixture, and the parent sets the final value before the group-B merge (the setting's value changes, not the contract). Preview shows the units against the budget.
- **Citations:** every cited row becomes `[C<n>]` with:
  - kind, table, row id, job id;
  - a bounded copy of the rendered fields and their `fields_sha256` at snapshot time;
  - the internal deep-link path (`/o/{org}/pcap/{job}?tab=findings&ref={id}`; the PDF prefixes `PUBLIC_BASE_URL`).

  Sources:
  - verified AI citations only, as `ai/service_outputs.deep_link` does;
  - rows the analyst selected;
  - note refs;
  - ATT&CK mapping sources.

  `report_citations` (append-only, index (org, kind, ref_id)) answers "which report versions cite this row" next to the M5 AI index.
- **AI sections:**
  - Only completed runs of this case's scope.
  - Only `supported` claims and labelled hypotheses. Unsupported claims are omitted with a count.
  - Flags are shown inline on each claim, and the "AI-generated, verify before acting" disclaimer is on the section and in the appendix. The `external` profile omits claims flagged `verdict_language` or `external_url` (counted, RT15).
  - Pseudonyms: each run's pseudonyms are **reversed with that run's map in both profiles**. The `external` profile then re-pseudonymizes the whole snapshot with **one report-level map**, so a pseudonym means the same value in every section and every run (RT2).
  - A canary-leak or refused run is never selectable.
- **Signing:**
  - Ed25519 (`cryptography`) over a manifest: `{schema, report_id, version, org_id, snapshot_sha256, snapshot_bytes, tlp, profile, finalized_at, finalized_by, kid}` in canonical JSON. The detached signature is stored in `report_versions`.
  - The private key is a compose secret `REPORT_SIGNING_KEYS_FILE` of the **api role only**. Public keys come from `REPORT_SIGNING_PUBLIC_KEYS` / `REPORT_SIGNING_ACTIVE_KID`. A committed dev pair (`dev-report-1`) is refused in prod; `scripts/gen_report_signing_keys.py` generates keys.
  - `GET /api/v1/report-signing-keys` publishes the public keys. It is **unauthenticated** and rate-limited, because the recipient of an external PDF has no account (RT22). The keys are also listed in DEPLOYMENT.
  - An import guard confines the private-key loader to `reports/signing.py`.
  - PAdES (pyHanko) is out of scope.
- **Storage:**
  - New MinIO buckets `reports` and `reports-test` (RT6):
    - Both are created `--with-lock` and versioned, with **no bucket default retention** (the evidence bucket has none either). A default retention would make MinIO demand `Content-MD5` on the renderer's presigned POST.
    - Retention is per object, GOVERNANCE, `EVIDENCE_LOCK_DAYS`: set by the API on the snapshot at finalize, and by the ingest-worker on an artifact after its re-hash.
    - `reports-test` gets the test-bucket lifecycle rule, and `api-test` uses it (`REPORTS_BUCKET=${REPORTS_TEST_BUCKET}`).
    - The api and ingest processes share the `cyberlab-api` MinIO user. Its policy gains get, version get, put and `PutObjectRetention` / `GetObjectRetention` on both buckets, and **no** `DeleteObject` / `DeleteObjectVersion`.
  - Keys are `{org}/{report}/{version}/snapshot.json` and `{org}/{report}/{version}/{render_id}.{ext}`.
  - The API reads exact versions and verifies the sha256 on every read (`core/storage.hash_version`).
  - Downloads are streamed by the API, never presigned to users.

**TLP and share policy** (decision; FIRST TLP 2.0)
- **Labels and order:** `investigations.tlp` ∈ `clear < green < amber < amber_strict < red`, default `amber` (backfilled for existing cases). They are rendered as `TLP:CLEAR` … `TLP:RED` in the FIRST colours on black. TLP marks the header and footer of every page and every export (≥ 12 pt), plus the CSV / STIX exports and the viewer banner.
- **Report TLP:** defaults to the case TLP, and **may not be less restrictive** unless the user has `org.update` and sends `acknowledge_tlp_downgrade`. The downgrade is audited as `report.tlp_downgraded`. A case TLP change follows the same rule.
  - **Finalize re-checks the rule against the case TLP at that moment (RT7).** If the case TLP was raised after the draft was written, finalize needs `org.update` plus `acknowledge_tlp_downgrade` in the finalize body (`409 tlp_below_case` otherwise), and the downgrade is audited.
  - Each cover prints the FIRST one-line definition of its label for recipients (RT23).
- **Share policy:** the case has `ai_excluded` and `ti_excluded`; an evidence item has an `evidence_share_policies` row with the same two flags. That table avoids touching the `evidence_immutable` trigger.
  - **TLP:RED implies both flags** (computed, not stored).
  - **Enforcement** goes through one frozen function, `investigations/policy.py: load_policy(...) → SharePolicy`, called at the service choke points rather than the routers (RT20):
    - by `ai/service_runs.request_run` and `preview` (`POST /ai/runs`, `/ai/context-preview`) → `409 policy_blocked` with `reason` (`case_ai_excluded`, `evidence_ai_excluded`, `tlp_red`);
    - by the incident builder's job selection, which skips excluded evidence. The count goes into `context_stats.policy_excluded`, which is **stored but not rendered into the prompt**, so the pinned M5 prompt digests and `prompt_version` do not change (RT20);
    - by `threat_intel/service_runs._request` for job-scope enrichments → `409 policy_blocked`;
    - by the analyst-worker before **every** provider request, including `count_tokens` (it also sends the content), and by the enrich-worker before each provider slice. A policy that changed after the request fails the run `failed / policy_blocked` and makes no call. The window between that re-check and the call in flight is a documented residual.
  - **Manual TI lookups** (`POST /ti/lookups`) carry no case scope, so typed values cannot be checked (RT20). This is a documented residual; the case and evidence pages hide "Look up" while TI is blocked.
  - Turning an exclusion **off** needs `integrations.manage`; turning it **on** needs `investigation.write`. Both are audited.
- **Profiles:**
  - `internal`: full detail and real names.
  - `external` (RT8): internal IPs, hosts and users are pseudonymized with the M5 pseudonymizer and the org's CIDRs / suffixes, applied to **every string field** of the snapshot. Only an allow-list of enum, hash, UUID, count and timestamp fields is exempt. The covered fields include case title and description, analyst sections, status reasons, distribution, evidence filenames, timeline titles, finding and alert text, IOC values, TI summaries, ATT&CK rationale, citation copies and AI text.
    - A **second whole-token pass** replaces every original value already in the map wherever it appears. The map is seeded first from hostname- and user-typed structured fields, so single-label names such as `FIN-SRV-01` and bare usernames in free text are also replaced.
    - No notes; custody IPs, user agents and actor names are replaced by roles; no deep links and no `base_url`.
    - Distribution text is required, and finalize requires `acknowledge_external_review`.
    - `finalized_by` in the manifest is a UUID, never a name.
  - TLP:RED and TLP:AMBER+STRICT need a `distribution` statement (≤ 500 characters) on the cover.

**Case management** (decision)
- **Notes:**
  - `analyst_notes` (logical note: case, creator, `current_version`, `pinned`, `include_in_reports`, soft delete `deleted_at/by`).
  - `analyst_note_versions` (append-only): body ≤ 20 000 characters of plain text, refs ≤ 20 typed `{kind, ref_id, job_id}` re-checked in scope, author, time.
  - An edit adds a version with `expected_version`. Only the author, or `org.update`, may edit or delete.
  - A deleted note keeps its versions, so history is preserved (§10).
- **IOC collections:**
  - `ioc_collections` per case: name ≤ 120, description ≤ 2 000.
  - `ioc_collection_items`: TI `ioc_type`, `value_norm`, `ioc_key` = M4 `compute_ioc_key`, unique (collection, ioc_key). Source is `job_ioc` (`job_id`, `ioc_id`) or `manual`; note ≤ 500; soft remove.
  - Items are normalized by the M4 TI normalizer, so collection items join `ti_results` history.
  - A case-wide aggregated IOC route dedups by `ioc_key` across the latest jobs.
  - Export as CSV (formula-injection safe), JSON or STIX 2.1 bundle. STIX indicators get deterministic uuid5 ids and the TLP 2.0 marking-definition (RT18). Those are the OASIS `cti-stix-common-objects` ids under extension `extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d`, frozen in the contract (CLEAR `94868c89-…`, GREEN `bab4a63c-…`, AMBER `55d920b0-…`, AMBER+STRICT `939a9414-…`, RED `e828b379-…`). STIX 2.1 core defines only TLP 1.0 ids. Exports are audited and defanged in CSV / JSON (`defang=true` default). Exports are never redacted; the export dialog says so.
- **Status:**
  - The existing `TRANSITIONS` stay.
  - Closing, reopening and archiving need a `reason` (≤ 500).
  - New `investigation_status_events` (append-only) feed the case timeline and the report.
- **ATT&CK case mapping:**
  - `case_attack_mappings` (technique id valid and not revoked in v20, `status` `confirmed | suspected | rejected`, rationale, source refs).
  - Suggestions come from capa capabilities, finding ATT&CK ids and **verified** AI `attack_techniques` of the case. They are never auto-confirmed.
  - A tactic-grouped matrix read.
- **Timeline:**
  - The merged timeline gains `note` (notes with `include_in_reports`) and `status` kinds. These entries have no evidence, so phase 1 makes `evidence_id` nullable in `timeline.Entry` and `TimelineEntryOut`, and adds `RefKindName.NOTE` / `STATUS` (RT10).
  - Export as CSV or JSON, ≤ 50 000 rows, streamed. CSV cells whose first non-whitespace character is `= + - @ \t \r` or a full-width `＝ ＋ － ＠` are prefixed with `'` (RT19). Audited.

**Data model** (migration **0012**; the M4/M5 conventions: FORCE RLS on every tenant table, composite tenant FKs, S/I grants plus per-column UPDATE, `forbid_mutation()` on append-only tables, no DELETE grant, named checks with `octet_length` caps)

| Table | Scope / grants | Notes |
|---|---|---|
| `investigations` (+cols) | existing (table-wide UPDATE) | `tlp` text check (`clear/green/amber/amber_strict/red`, default `amber`), `ai_excluded`, `ti_excluded` bool default false |
| `investigation_status_events` | tenant, append-only | inv (composite FK), `from_status`, `to_status`, `reason` ≤ 500, actor, `occurred_at` |
| `evidence_share_policies` | tenant; S/I + UPDATE (`ai_excluded`, `ti_excluded`, `updated_by`, `updated_at`) | PK `evidence_id` (composite FK) |
| `analyst_notes` | tenant; S/I + UPDATE (`current_version`, `pinned`, `include_in_reports`, `deleted_at`, `deleted_by`, `updated_at`) | inv FK, `created_by`; trigger: `current_version` monotonic, delete fields set once |
| `analyst_note_versions` | tenant, append-only | PK (`note_id`, `version`), `body` ≤ 20 000 chars, `refs` jsonb array ≤ 20, author |
| `ioc_collections` | tenant; S/I + UPDATE (`name`, `description`, `archived_at`, `updated_at`) | inv FK, unique (inv, lower(name)) |
| `ioc_collection_items` | tenant; S/I + UPDATE (`removed_at`, `removed_by`, `note`) | collection FK, `ioc_type`, `value_norm` ≤ 2 048, `ioc_key` ~ sha256, unique (collection, ioc_key), `source`, `job_id`, `ioc_id` (both or neither), `added_by` |
| `case_attack_mappings` | tenant; S/I + UPDATE (`status`, `rationale`, `sources`, `updated_by`, `updated_at`) | inv FK, `technique_id` ~ `^T\d{4}(\.\d{3})?$`, unique (inv, technique_id), `sources` jsonb ≤ 32 entries |
| `reports` | tenant; S/I + UPDATE (`title`, `tlp`, `profile`, `draft`, `distribution`, `status`, `revision`, `latest_version`, `updated_at`) | inv FK, `template` (`incident_v1`), `status` `draft/discarded` (trigger: discarded only without versions; `revision` +1 per write; `latest_version` monotonic), `draft` ≤ 1 MiB (8 sections × 20 000 characters of non-ASCII text exceed 256 KiB, RT9; the request schema answers 422 before the DB check) |
| `report_versions` | tenant, append-only | unique (report, version); `schema`, `tlp`, `profile`, `snapshot_sha256`, `snapshot_bytes`, `object_key`, `object_version_id`, `manifest` jsonb ≤ 4 KiB, `signature` (b64), `kid`, `section_counts` ≤ 4 KiB, `change_note` ≤ 500 (RT23), `finalized_by/at` |
| `report_citations` | tenant, append-only | version FK, `cite_no`, `kind`, `ref_table`, `ref_id` text, `job_id`, `fields_sha256`, `source` (`ai/selection/note/attack`), `ai_citation_id` nullable; unique (version, cite_no); index (org, kind, ref_id) |
| `report_renders` | tenant; S/I + UPDATE (`status`, `error_code`, `sha256`, `bytes`, `pages`, `object_version_id`, `renderer_version`, `started_at`, `finished_at`) + transition trigger | version FK, `format` (`pdf/html/md`; DOCX deferred, RT12), `status` `queued → running → succeeded / failed` (finals immutable), `token_sha256`, `requested_by`; unique (version, format, renderer_version) among non-failed renders |
| `report_render_index` | system lookup like `analysis_job_index` / `ti_run_index` | render → org, status, `dispatched_at`, `deadline_at`, attempts |

## Red-team changes (2026-11-06)

**Reviewers and sources.** Four hostile reviewers (security, reliability, product / legal, scope / parallelism) checked this plan and the research report against the code:
- API core: `core/{config,rbac,tenancy,storage}.py`;
- modules: `ai/{text,service_outputs,contracts}.py`, `ai/context/pseudonymize.py`, `investigations/{models,service,timeline,schemas}.py`, `threat_intel/{router_runs,service_runs}.py`;
- workers: `workers/{tasks,reaper,enrich,analyst}.py`;
- migrations 0001 / 0009 / 0011;
- worker kit: `packages/py-worker-kit/{sandbox,seccomp,transfer}.py` and `tests/test_isolation.py`;
- infra: the static worker Dockerfile, `docker-compose.yml`, `infra/redis-broker/entrypoint.sh`, `infra/minio/{init.sh,api-policy.template.json}`;
- scripts and web: `scripts/lane-test.sh`, `apps/web/lib/{roles,audit-actions}.ts`.

They also checked PyPI, OSV / GHSA, the WeasyPrint 70.0 docs and source, python-docx 1.2.0, Jinja2 3.1.6, the OASIS TLP 2.0 STIX extension and the FIRST TLP page.

**Result:** 32 findings: 2 High, 13 Medium, 17 Low. 24 were accepted and applied, and 8 rejected. The seed questions are answered by RT1–RT3, RT7, RT8, RT10, RT11, RT20, RT21 and RT25–RT27.

| ID | Finding (failure scenario) | Severity | Disposition |
|---|---|---|---|
| RT1 | **Signed but unrenderable.** The caps allow an 8 MiB snapshot and 1 000 pages, while the render sandbox has 768 MiB `RLIMIT_AS`, a 1 GiB container and 90 s of CPU. WeasyPrint holds the whole document in memory (upstream reports about 2.6–3 GB for 1 500 pages, issue #671). A finalized version, immutable by design, can therefore never produce its PDF: `oom` / `timeout` forever. The page cap is checked only after the memory is spent. | High | Accepted → a render budget in the contract (`render_units`); finalize refuses `422 report_too_large_to_render`; page cap 300; artifact cap 32 MiB; phase 4 calibrates on a worst-case-at-budget fixture and the parent fixes the value before the merge; preview shows the units (plan Snapshot; phases 1, 3, 4, 7, 9). |
| RT2 | **Pseudonym collisions in external reports.** In `external`, AI sections "keep the run's pseudonyms", while the rest of the snapshot is pseudonymized by the report. Each M5 run tree numbers independently, so `INT_HOST_1` in an AI section, in another run and in the IOC table can be three different hosts. That is misattribution inside a signed deliverable. | High | Accepted → every run is reversed with its own map in both profiles, then `external` applies **one** report-level map to the whole snapshot; a test asserts one value ↔ one pseudonym across all sections and runs (plan AI sections; phase 3). |
| RT3 | **The sandbox reuse does not fit the worker kit.** `run_tool` fixes `RLIMIT_FSIZE` at 2 GiB and `NOFILE` at 1024 and sets no `NPROC`. The libseccomp filter is code, not a JSON profile; it denies only AF_INET / AF_INET6 / AF_PACKET (with `EACCES`, not `EPERM`) and leaves `io_uring` open (`IORING_OP_SOCKET`). Phase 4 cannot edit `packages/py-worker-kit`. The plan's "uid 10002 worker" cannot `setuid` to 10003; the analyzers run as root with `cap_add`. | Medium | Accepted → phase 1 extends the worker kit (`run_tool(..., rlimits=…)`, `deny_network(extra_domains=(AF_NETLINK,), deny_io_uring=True)`) with tests; the worker runs as root with the analyzers' `cap_add`; tests expect `EACCES` (plan Trust; phases 1, 4). |
| RT4 | **The worker process model breaks the limits.** Celery `--pool solo` ignores `max_tasks_per_child` and does not enforce the hard time limit, so one parent persists across tenants. `python -I -S` drops the venv's site-packages, so the subprocess cannot import WeasyPrint. A 64 MiB `/tmp` cannot hold the snapshot, the HTML and the artifact. | Medium | Accepted → prefork `--concurrency 1 --max-tasks-per-child 1` (the analyzers' command line); `python -I -B`; `MALLOC_ARENA_MAX=2`; a root-owned `/work` tmpfs of 96 MiB; `cyberlab_worker.sandbox.reset` before every render (plan Trust; phases 1, 4). |
| RT5 | **Renders expire in the queue.** One single-concurrency worker, caps of 6 per org and 20 global, a 300 s deadline, up to 100 s per render, and finalize queuing every requested format. The renders behind the third one time out while still queued, and the reaper fails them. | Medium | Accepted → `REPORT_ACTIVE_RENDERS_PER_ORG` 2 and `_GLOBAL` 4 per replica (documented scaling); deadline 600 s; finalize queues the PDF only, other formats on demand (phases 1, 3, 4). |
| RT6 | **No test bucket, and a wrong retention model.** `api-test` runs on `MINIO_TEST_BUCKET` / `RESULTS_TEST_BUCKET`, but the plan has only an object-locked `reports`, so lane tests would leave locked objects in the dev bucket. The evidence bucket has no default retention (`set_retention` per object), so "retention like evidence" is wrong, and a default retention makes MinIO demand `Content-MD5` on presigned POST uploads. api and ingest share one MinIO user, so a separate "ingest read" grant is not possible. | Medium | Accepted → `reports` and `reports-test` (lifecycle rule), no default retention, per-object GOVERNANCE retention by the API (snapshot) and ingest (artifact), one policy with retention actions and no delete (plan Storage; phases 1, 3, 4). |
| RT7 | **TLP downgrade through the draft.** The TLP rule runs only on draft writes. If the case TLP is raised after a draft at the old level, finalize signs a report below the case TLP without `org.update` or an acknowledgement. | Medium | Accepted → finalize re-checks against the current case TLP, with an ack in the finalize body (`409 tlp_below_case`) and an audit (plan TLP; phases 3, 7). |
| RT8 | **External redaction leaks.** The M5 pseudonymizer is pattern-based, so single-label hosts (`FIN-SRV-01`) and bare usernames in free text pass. The field list was implicit: case title and description, analyst sections, status reasons, evidence filenames, timeline titles and ATT&CK rationale were not named. Deep links and `base_url` expose the platform host and org UUID. | Medium | Accepted → every string field except an allow-list; a second whole-token pass over the values already in the map, seeded from structured hostname and user fields; no deep links or `base_url`; `acknowledge_external_review`; sentinel tests with single-label names (plan Profiles; phases 3, 7). |
| RT9 | **Analyst text is truncated or rejected.** "Every free-text field ≤ 4 096" silently cuts the 20 000-character executive summary and notes in the signed report. `reports.draft` ≤ 256 KiB is below 8 × 20 000 characters of Vietnamese UTF-8, so a valid draft hits the DB check as a 500. | Medium | Accepted → `AnalystText` ≤ 20 000 never truncated, `BoundedText` 4 096 for evidence-derived text; draft cap 1 MiB with a 422 at the schema (plan Snapshot, Data model; phases 1, 3). |
| RT10 | **Timeline contract gap.** `timeline.Entry.evidence_id` and `TimelineEntryOut.evidence_id` are non-null UUIDs, and `RefKindName` has no note or status, so the new kinds cannot be returned. "`page(...)` keeps its signature" contradicts the new `kinds` filter, and the timeline route lives in phase 2's `investigations/router.py`. | Medium | Accepted → phase 1 makes `evidence_id` nullable, adds the ref kinds, `page(..., kinds=None)` and the route's `kinds` parameter (Frozen interfaces; phases 1, 5, 6). |
| RT11 | **Missing cross-phase entry points.** The snapshot builder (phase 3) needs the case-wide IOC aggregation that phase 2 writes. The viewer has no JSON route for a version (only the audited snapshot attachment). `EvidenceOut` flags need `evidence/{service,repository}.py`, which no phase owns. The audit filter list `lib/audit-actions.ts` lacks the M6 actions. | Medium | Accepted → frozen stub `ioc_collections/case_iocs.py: case_iocs(...)` (owned by phase 2); `GET /reports/{rid}/versions/{v}/content` (`evidence.read`, phase 3); phase 2 owns the evidence service and repository; phase 1 adds the audit actions (Frozen interfaces; phases 1, 2, 3, 7). |
| RT12 | **DOCX is YAGNI and breaks the determinism gate.** python-docx 1.2.0 writes zip members with the current time (`writestr`), so "byte-identical DOCX" fails phase 9. It adds a fourth renderer, a second document writer and its checks to a 14 h phase. PDF is the deliverable, and Markdown covers editable text. | Medium | Accepted → DOCX deferred (Out of scope); format check `pdf/html/md`; `python-docx` dropped (phases 1, 4, 7, 8, 9). |
| RT13 | **108 h is optimistic.** Phase 1 carries 12 tables, about 40 stub routes, call sites in four M4/M5 files, the worker-kit extension and the shared web pieces (about 22 h). Phase 4 builds the trusted render pipeline, the sandbox and three renderers (about 16 h). Phase 3 gains the content route and the redaction second pass (15 h). | Medium | Accepted → 22 + 12 + 15 + 16 + 8 + 10 + 12 + 6 + 12 = 113 h with DOCX cut; critical path about 56 h (Phases). |
| RT14 | **Finalize holds a transaction too long.** One transaction plus an advisory lock spans the multi-query build at READ COMMITTED (sections read at different instants), the 8 MiB MinIO put and signing, under the app role's 60 s `idle_in_transaction` and 30 s statement timeouts (M5 RT7). | Medium | Accepted → build in one read-only REPEATABLE READ transaction; put and sign outside any transaction; then a short write transaction re-checks `revision`, `latest_version` and the TLP rule; a conflict leaves a logged orphan (plan Architecture; phase 3). |
| RT15 | **AI flags printed as fact.** Claims flagged `verdict_language`, `external_url` or `command_like` are printed in a signed PDF, and PDF viewers auto-link plain URLs in text. | Low | Accepted → flags inline per claim; `external` omits `verdict_language` / `external_url` claims (counted); AI and evidence text defanged in the snapshot (plan AI sections; phases 3, 4, 7). |
| RT16 | **Fetcher facts.** In WeasyPrint 70, `data:` URIs, attachments given as filenames, `@font-face url()` and `@import` all go through `URLFetcher`, and function-style fetchers are gone. CVE-2026-106443 (EPS → Ghostscript RCE, ≤ 69.0) and fonttools CVE-2025-66034 were not in the research. | Low | Accepted → the fetcher allows nothing (constant `CSS(string=…)`, fontconfig fonts, attachments as bytes); no Ghostscript in the image; `fonttools>=4.60.2` (plan Renderer; phases 1, 4). |
| RT17 | **Reproducibility details.** `Attachment.created/modified` default to now; `srgb` became `output_intent` in 69.0; Debian font or Pango updates change bytes across image rebuilds. | Low | Accepted → fixed attachment dates (`finalized_at`), relationship `Source`; determinism claimed per image and renderer version (phases 4, 9). |
| RT18 | **STIX marking ids.** The TLP 2.0 marking-definition ids are OASIS `cti-stix-common-objects` ids under extension `extension-definition--60a3c5c5-…`, not "FIRST ids". STIX 2.1 core defines only TLP 1.0. | Low | Accepted → the five ids frozen in the contract, plus a test against the published objects (plan IOC collections; phases 1, 2). |
| RT19 | **Export hygiene.** Downloaded HTML opened from disk gets no CSP header. A newline inside a Markdown table cell breaks the row. `csv_safe` misses leading whitespace and full-width `＝ ＋ － ＠`. | Low | Accepted → meta CSP in the HTML artifact; `⏎` in Markdown cells; the extended `csv_safe` rule (plan Templates, Timeline; phases 1, 4). |
| RT20 | **Policy call-site details.** `POST /ti/lookups` has no case scope. `count_tokens` also sends content to the provider. The checks belong at the service choke points. An always-present `policy_excluded` rendered in the prompt would change the pinned M5 prompt digests. | Low | Accepted → manual lookups are a documented residual and the case page hides "Look up" while blocked; the re-check precedes every provider request; checks in `request_run` / `preview` / `_request`; the stat is stored, not rendered (plan TLP and share policy; phases 1, 6, 8). |
| RT21 | **Test plumbing.** `apps/api/tests/container/` is not in the report-worker image. `lane-test.sh` wraps only `api-test`, so "report-worker-test counts as a slot" had no mechanism. `transfer.download` needs the snapshot size. `useOrgRole` does not exist (`lib/roles.ts: can`). | Low | Accepted → `apps/workers/report/tests/test_isolation.py`; `lane-test.sh --service report-worker-test` with the same slot lock (phase 1); `snapshot_bytes` in the message; wording fixed (phases 1, 4, 6, 9). |
| RT22 | **External verifiers cannot get the keys.** The public-keys route requires a login, which an external PDF recipient does not have. | Low | Accepted → unauthenticated, rate-limited route, and the keys listed in DEPLOYMENT (plan Signing; phases 1, 8). |
| RT23 | **Missing document control.** A "professional report" has no version history or change note, and recipients get no TLP definition. | Low | Accepted → `change_note` ≤ 500 at finalize (`report_versions` column), a document-control table of prior versions in the snapshot, and the FIRST one-line definition on the cover (phases 1, 3, 4, 7). |
| RT24 | **Text-rule drift.** "Category Cf" evaluated at runtime differs between Python 3.12 `unicodedata` and browser ICU. Defang was applied both in the snapshot and in the renderer filter. | Low | Accepted → `vis_rules.json` is a materialized range list generated from the M5 rules by a script; defang happens once, in the builder; renderers and the viewer apply `vis` only (plan Templates; phases 1, 3, 4, 7). |
| RT25 | Use `network_mode: none` plus a file-drop bridge for the renderer (the research recommendation). | Medium | Rejected → the worker parent needs the broker, and the render subprocess already has no inet / netlink / packet sockets at the syscall level; a bridge would add a trusted file mover. This is the analyzers' accepted pattern. |
| RT26 | Move the Ed25519 key into its own signer process or role. | Low | Rejected → an API compromise already writes the DB rows and the objects; a signer adds a service for no new guarantee. KMS / HSM stays out of scope (residual). |
| RT27 | The ingest-worker should verify that the rendered PDF embeds the signed snapshot. | Low | Rejected → that would parse attacker-produced PDFs in the trusted zone. Ingest stays parse-free (magic, size, re-hash); `scripts/verify_report.py` checks embedding offline, and phase 9 tests it. |
| RT28 | Cut Markdown and STIX as well (YAGNI). | Low | Rejected → Markdown is the ticket / wiki format and is cheap with the escaper; STIX 2.1 is the standard IOC sharing format and carries the TLP marking. |
| RT29 | Store the report-level pseudonym map so analysts can answer "which host is INT_HOST_3?". | Low | Rejected for M6 → no route or retention policy exists for it; documented residual. The `internal` version of the same report answers it. |
| RT30 | Split migration 0012 into two migrations (case management and reports). | Low | Rejected → one owner (phase 1), one upgrade / downgrade test; 0013 stays reserved for the parent. |
| RT31 | TLP:RED report downloads should need more than `evidence.read` (viewers can download). | Low | Rejected → RBAC is org-wide and unchanged in M6; per-case access control is out of scope. Every download is audited (residual in THREAT_MODEL). |
| RT32 | Compute the timeline `note` entries from the latest note version instead of the first. | Low | Rejected → the entry marks when the note was written; the edits are visible in the note history. |

## Phases

| Phase | Name | Group | Depends on | Status |
|-------|------|-------|------------|--------|
| 1 | [Foundation contracts migration 0012 and renderer service](./phase-01-foundation-contracts-migration-0012-and-renderer-service.md) | A | — | Pending |
| 2 | [Case management API notes IOC collections status and TLP](./phase-02-case-management-api-notes-ioc-collections-status-and-tlp.md) | B (2a, lane 2) | 1 | Pending |
| 3 | [Report snapshot versioning citations and signing](./phase-03-report-snapshot-versioning-citations-and-signing.md) | B (2b, lane 3) | 1 | Pending |
| 4 | [Isolated report renderer worker](./phase-04-isolated-report-renderer-worker.md) | B (2c, lane 4 + report-worker-test) | 1 | Pending |
| 5 | [ATT&CK case mapping and timeline export](./phase-05-att-ck-case-mapping-and-timeline-export.md) | B (2d, lane 5) | 1 | Pending |
| 6 | [Case management frontend](./phase-06-case-management-frontend.md) | B (2e, web only) | 1 (frozen contracts) | Pending |
| 7 | [Report builder and viewer frontend](./phase-07-report-builder-and-viewer-frontend.md) | B (2f, web only) | 1 (frozen contracts) | Pending |
| 8 | [Docs and threat model](./phase-08-docs-and-threat-model.md) | C | B merged | Pending |
| 9 | [Hardening e2e metric and gate](./phase-09-hardening-e2e-metric-and-gate.md) | D | all | Pending |

Effort (RT13): 22 + 12 + 15 + 16 + 8 + 10 + 12 + 6 + 12 = 113 h, with DOCX cut. Critical path: 1 → max(B) → 8 → 9, about 22 + 16 + 6 + 12 = 56 h of wall time with six group-B agents.

## Dependencies and parallelism

**Cross-plan:** blocked by `261105-2100-cyberlab-m5-ai-analyst`. Its gate (`pnpm verify:prod`) must be green and merged first. Phase 1 confirms that the alembic head is `0011` and that the M5 / M4 files it edits (`ai/service_runs.py`, `ai/context/builder.py`, `ai/contracts.py`, `workers/analyst.py`, `threat_intel/service_runs.py`, `workers/enrich.py`) are final.

**Group A: phase 1, one agent; frozen when committed.** Only the parent changes frozen files afterwards. A change request from a later phase goes to the parent, which decides and broadcasts it.

**Frozen interfaces** (phase 1 notes record the exact signatures):
1. **Migration `0012_reports_case_mgmt.py`** and the models:
   - `investigations/models.py` (+ columns, `InvestigationStatusEvent`, `EvidenceSharePolicy`);
   - `notes/models.py`, `ioc_collections/models.py`, `case_attack/models.py`, `reports/models.py`.
   - Later schema needs go into **0013**, assigned by the parent.
2. **Snapshot contract** `packages/py-jobs/src/cyberlab_jobs/report.py`:
   - `REPORT_SCHEMA = "cyberlab.report.v1"` and the models: `ReportSnapshot`, `CaseSection`, `AnalystSections`, `EvidenceItem`, `CustodyItem`, `JobItem`, `FindingItem`, `AlertItem`, `IocItem`, `TiItem`, `AttackItem`, `TimelineItem`, `NoteItem`, `AiSection`, `AiClaim`, `Citation`, `Manifest`;
   - the caps, `BoundedText` (4 096) and `AnalystText` (20 000) (RT9), `canonical_json(model) -> bytes`, `render_units(snapshot) -> int` (RT1), `TLP` enum + `TLP_ORDER` + `TLP_COLOURS` + `TLP_DEFINITIONS` (RT23) + `STIX_TLP_MARKINGS` (the five OASIS ids, RT18), `Profile`, `DocumentControlItem` (RT23);
   - the render messages `ReportRenderMessageV1{render_id, org_id, format, snapshot_url, snapshot_sha256, snapshot_bytes, manifest_b64, signature, kid, finalized_at, upload: PresignedPost, token, deadline}` (RT17, RT21) and `ReportRenderedV1{render_id, token, status, sha256, bytes, pages, renderer_version, error_code}`;
   - task names `REPORT_RENDER`, `REPORT_RENDERED` and `Queues.report`.
3. **Contracts per module:**
   - `investigations/policy.py`: implemented in phase 1, because the call sites live in M5/M4 files. `SharePolicy{ai_blocked, ti_blocked, reasons, excluded_evidence_ids}`, `async load_policy(session, org_id, *, investigation_id=None, job_ids=(), evidence_ids=()) -> SharePolicy`, `PolicyBlocked(code, reason)`, `tlp_at_least(a, b)`.
   - Request and response **schemas** for every new route: `notes/schemas.py`, `ioc_collections/schemas.py`, `case_attack/schemas.py`, `reports/schemas.py`, `case_timeline/schemas.py`, and the additions to `investigations/schemas.py`:
     - `tlp`, `ai_excluded`, `ti_excluded`, `status_reason`, `StatusEventOut`, `EvidenceSharePolicyIn/Out`;
     - timeline kinds `note` and `status`, with `TimelineEntryOut.evidence_id` **nullable** (RT10).

     The finalize body carries `acknowledge_tlp_downgrade`, `acknowledge_external_review` and `change_note` (RT7, RT8, RT23).
   - Phase 1 freezes them, so `pnpm gen:contracts` can run once and the two frontend phases build against real types.
4. **`app/core/csv_safe.py`** (implemented in phase 1): `csv_safe(cell)` and `write_csv(rows, header_comment)`, shared by phases 2 and 5. **`packages/py-worker-kit`** (extended in phase 1, RT3): `run_tool(..., rlimits: Rlimits | None = None)` and `seccomp.deny_network(extra_domains=(), deny_io_uring=False)`. The defaults keep the analyzers unchanged. **`core/tenancy.tenant_session(..., snapshot_read: bool = False)`** (phase 1, RT14): it opens the transaction as `REPEATABLE READ READ ONLY` before the `set_config` statement. `SET TRANSACTION` must come before any query, so the builder cannot do this itself. **`app/core/signing.py`** (implemented in phase 1): `load_signing_keys(path) -> dict[kid, Ed25519PrivateKey]` (import-guarded: only `reports/signing.py`), `load_public_keys(json) -> dict[kid, Ed25519PublicKey]`, `sign(manifest_bytes, kid, keys) -> str`, `verify(manifest_bytes, signature_b64, kid, public_keys) -> bool`. Plus `infra/reports/dev-signing-private.json` (kid `dev-report-1`) and `scripts/gen_report_signing_keys.py`.
5. **Cross-phase entry points** (stubs raising `NotImplementedError`; ownership moves to the named phase, which never changes the signature):
   - `reports/snapshot.py`: `async build_snapshot(session, org_id, user_id, report: Report, *, now) -> BuiltSnapshot{snapshot: ReportSnapshot, citations: list[CitationRow], counts}` (phase 3);
   - `reports/cited_by.py`: `async cited_by(session, org_id, kind, ref_id) -> CitedByOut` (phase 3);
   - `reports/dispatch.py`: `async create_render(session, org_id, user_id, version: ReportVersion, fmt) -> ReportRender` and `async dispatch_render(render_ids) -> None` (phase 4);
   - `reports/render_ingest.py`: `async handle_rendered(msg: ReportRenderedV1) -> None`, already called by the `report.rendered` ingest task registered in `workers/tasks.py` (phase 4);
   - `workers/reaper.py`: `async reap_report_renders() -> int` (returns 0; already called by `reap`; phase 4);
   - `case_attack/suggest.py`: `async suggestions(session, org_id, investigation_id) -> list[AttackSuggestion]` (phase 5);
   - `ioc_collections/case_iocs.py`: `async case_iocs(session, org_id, investigation_id, *, types=None, q=None, limit, cursor=None) -> CaseIocPage` (phase 2; the phase-2 route and the phase-3 snapshot builder both call it, RT11);
   - `investigations/timeline.py` (RT10): phase 1 extends the signature once to `page(..., kinds: Sequence[TimelineKind] | None = None)` (ignored until phase 5), makes `Entry.evidence_id` optional and adds `RefKindName.NOTE` / `STATUS`. Phase 1 also passes `kinds` from the existing route in `investigations/router.py`. Phase 5 then adds the two kinds without changing the signature.
6. **Routers:** empty routers `notes/router.py`, `ioc_collections/router.py`, `case_attack/router.py`, `case_timeline/router.py`, `reports/router.py`, `reports/router_renders.py`, registered in `app/main.py`. **Every new route path, method, permission and response model is frozen in phase 1 as a stub that answers `501 not_implemented`**, so the contracts and the IDOR enumerator see them from the start.
7. **Test helpers:**
   - `tests/case_helpers.py`: seed a case with TLP / flags, notes, a collection, a mapping;
   - `tests/report_helpers.py`: seed a report draft, a version with a snapshot object (in `reports-test`), a render with token, `fake_snapshot()`, test signing keys;
   - `tests/fixtures/report/hostile_snapshot.json`: `</style>`, `<img src=http://…>`, `url(file:///etc/passwd)`, U+202E, zero-width, 64 KiB strings, CSV formula cells, Markdown control sequences;
   - `tests/fixtures/report/golden_snapshot.json` (valid, small).
8. **IDOR case modules:** `tests/security/test_idor_routes.py` merges `idor_cases_case.py` (phase 2), `idor_cases_reports.py` (phase 3), `idor_cases_renders.py` (phase 4) and `idor_cases_attack.py` (phase 5), all created empty with their victim extenders' signatures. Each module also exports `PENDING_ROUTES`, which phase 1 fills with that module's routes. The enumerator skips those routes and reports them; the owning phase empties its own set, and phase 9 asserts that every set is empty.
9. **`tests/conftest.py` is frozen in group B.**

**Group B: phases 2–7, in parallel** (one subagent each, own worktree from the phase-1 commit, file-disjoint). Each phase's tests pass in isolation against the phase-1 stubs, helpers and frozen schemas. Cross-phase behaviour is tested after the merge (phase 9). Lanes run only their own test files plus `ruff` / `mypy` (API) or `pnpm --filter web lint typecheck test` on their own files (web). Nobody runs `pnpm verify` or the full suite in a lane.

| Phase | Owns (creates or edits; nobody else touches these in group B) |
|---|---|
| 2 (2a) | `investigations/{router,service,repository}.py` (route bodies; the frozen `schemas.py` classes are not changed, and the existing timeline route keeps calling `timeline.page` with `kinds` as phase 1 left it), `evidence/router.py` + `evidence/share_policy.py` (share-policy routes) + `evidence/{service,repository}.py` (the flags on `EvidenceOut` reads, RT11), `app/modules/notes/**` and `app/modules/ioc_collections/**` (after the stubs), `tests/security/idor_cases_case.py`, `tests/integration/test_case_{status,tlp,policy_api,notes,ioc_collections,ioc_exports,case_iocs}.py`, `tests/unit/test_stix_export.py` |
| 3 (2b) | `app/modules/reports/{service,repository,snapshot,snapshot_*,citations,cited_by,redact,signing,storage,router}.py` (not `dispatch.py`, `render_ingest.py`, `router_renders.py`), `scripts/verify_report.py`, `tests/security/idor_cases_reports.py`, `tests/integration/test_report_{drafts,finalize,snapshot,citations,cited_by,redaction,signing,storage}.py` (the `content` route is tested in `storage`), `tests/unit/test_report_canonical.py`, `test_verify_report_script.py` |
| 4 (2c) | `apps/workers/report/**` (Dockerfile, worker, sandbox wrapper, templates, CSS, fonts config, renderers, tests), `app/modules/reports/{dispatch,render_ingest,router_renders}.py`, `app/workers/reaper.py` (`reap_report_renders`), `tests/security/idor_cases_renders.py`, `tests/integration/test_report_{renders,render_ingest,render_reaper}.py` |
| 5 (2d) | `app/modules/case_attack/**` (after the stubs), `investigations/timeline.py`, `app/modules/case_timeline/**` (export), `tests/security/idor_cases_attack.py`, `tests/integration/test_case_attack*.py`, `test_timeline_kinds.py`, `test_timeline_export.py` |
| 6 (2e) | `apps/web/lib/{case,notes,ioc-collections,case-attack}.ts` (+ tests), `lib/use-case.ts`, `components/investigations/**`, `components/notes/**`, `components/ioc-collections/**`, `components/case-attack/**`, `components/timeline/**`, `app/(app)/o/[orgId]/investigations/[invId]/**`, `app/(app)/o/[orgId]/evidence/[evidenceId]/page.tsx`, `components/ai/policy-blocked.tsx` |
| 7 (2f) | `apps/web/lib/{reports,report-format}.ts` (+ tests), `lib/use-reports.ts`, `components/reports/**` (after the phase-1 `case-reports-panel.tsx` stub), `app/(app)/o/[orgId]/reports/**`, `lib/nav.ts` (Reports no longer "planned") |

- **Shared files touched only by phase 1:**
  - `pyproject.toml` / `uv.lock` (none expected for the API; the renderer has its own `apps/workers/report/pyproject.toml`, created by phase 1 with the pinned dependencies and lock);
  - `core/config.py`, `core/tenancy.py` (`snapshot_read`, RT14), `app/main.py`, `app/models.py`;
  - `workers/{celery_app,tasks}.py`, `workers/reaper.py` (the stub);
  - `ai/service_runs.py`, `ai/context/builder.py` (incident selection), `ai/contracts.py` (`ContextStats.policy_excluded`), `workers/analyst.py` (the policy call sites, RT20);
  - `threat_intel/service_runs.py` (enrichment policy), `workers/enrich.py`;
  - `investigations/{router,schemas,timeline}.py` for the RT10 timeline signature only, before group B starts (afterwards phase 2 owns the router and phase 5 the timeline);
  - compose files, `.env.example`, `infra/redis-broker/entrypoint.sh`, `infra/minio/{init.sh,api-policy.template.json,reports-test-lifecycle.json}`, `scripts/lane-test.sh` (`--service report-worker-test`, RT21);
  - `packages/py-jobs/**`, `packages/py-worker-kit/**` (RT3), `packages/contracts/**` (generated once after phase 1, then after the group-B merge);
  - `apps/web/lib/audit-actions.ts` (the M6 actions, RT11);
  - `tests/conftest.py`, `tests/security/test_idor_routes.py`;
  - `tests/unit/test_tenant_session_guard.py`, `tests/unit/test_*import_guard.py`, `tests/integration/test_rls_coverage.py`, `test_append_only.py`;
  - `apps/web/components/reports/case-reports-panel.tsx` (stub), `apps/web/lib/tlp.ts`, `components/tlp/**` and `lib/vis-rules.json` with its generator `scripts/gen_vis_rules.py` (shared, implemented in phase 1, RT24);
  - the one-line `policy-blocked` imports in the M4/M5 AI and TI trigger components are the only phase-6 exception (listed in its notes).

  The `cyberlab/api:dev` and `cyberlab/report-worker:dev` images are built once after phase 1.
- **Group B merge (parent):**
  1. Merge the six worktrees. They are file-disjoint, so any conflict is a plan bug.
  2. Run the full API suite on the main stack.
  3. Run `pnpm gen:contracts` and check for no drift from the phase-1 contracts. A drift is a parent decision.
  4. Run `pnpm --filter web test typecheck`.
  5. Fix seams in the owning phase's files, one commit per phase.
- **Group C: phase 8** (docs) after the merge. It may run while the parent fixes seams.
- **Group D: phase 9 last.** It is the only phase allowed to touch other phases' files, and only for gate fixes.
- **One commit per phase.** The stack stays deployable after each: the new routes answer 501 until their phase lands, the report-worker no-ops (`not_implemented`), and the policy defaults allow everything that M5 allowed.

### Parallel execution on this host (the M5 lane scheme, `scripts/lane-test.sh`)

1. **One shared infra stack**, started by the parent after the M5 verify gate: `postgres`, `redis`, `redis-broker`, `minio` (+ init). Stop `web`, `gateway`, the analyzers, `enrich-worker`, `analyst-worker` and the test-profile workers during group B.
2. **Worktrees** `..\cyber-wt\m6-b{n}` (`-b m6/b{n}` from the phase-1 commit), with `.env` copied in.
3. **API lanes:** phase 2 → lane 2, phase 3 → lane 3, phase 4 → lane 4, phase 5 → lane 5.
   - Run with `scripts/lane-test.sh <lane> uv run pytest -q -p no:cacheprovider <own paths>` from the worktree.
   - The databases `cyberlab_b{2..5}_test` exist from M5; the conftest migrates them to 0012.
   - At most three lane containers at once (`LANE_SLOTS=3`).
   - Lanes never `up`, `down`, `build`, `restart` or `stop`.
4. **Phase 4 renderer tests** run in `report-worker-test`, as `scripts/lane-test.sh 4 --service report-worker-test pytest -q tests/` (about 1 GB). The wrapper takes a lane slot from the same lock as `api-test` (RT21).
   - The integration test that needs a real render through the broker (`test_report_renders.py::*_end_to_end`) is a **heavy step**: the parent runs it alone with `report-worker-test` up after the other lanes finish.
5. **Web lanes (phases 6, 7):** host `pnpm --filter web test -- <own paths>`, `typecheck` and `lint`, against the phase-1 contracts and mocked fetch (MSW or the existing test pattern). They need no containers and no lane slot.
6. **Fallback** when worktrees misbehave on Windows: the M5 fallback (main tree, lane variables in the shell, `python -m compileall` before each run).

## Definition of done

- **Case management:**
  - Analysts write, edit (versions kept) and delete notes, and the history stays readable.
  - IOC collections are built from job IOCs or manual entries, normalized and deduplicated, and export to CSV, JSON and STIX 2.1 with TLP marking.
  - Closing, reopening or archiving needs a reason and shows in the history and the timeline.
  - TLP is set per case, and downgrades need `org.update` plus an acknowledgement.
- **Share policy:**
  - With `ai_excluded`, `ti_excluded` or TLP:RED on a case or evidence, AI runs, previews and TI enrichments for it are refused (`409 policy_blocked`).
  - Incident summaries skip excluded evidence, with a count.
  - A worker re-check fails an in-flight run `policy_blocked` without a provider call (ai-mock / ti-mock call counters prove it).
- **ATT&CK:** analysts confirm, suspect or reject techniques from suggestions (capa, findings, verified AI) or by id. Revoked or unknown ids are refused, and the matrix read groups by tactic.
- **Reports:**
  - A draft is finalized into an immutable, signed version, and a second finalize creates v2. Finalize refuses a version over the render budget, and a TLP below the current case TLP without the ack (RT1, RT7).
  - `external` versions use one pseudonym map for the whole report, and no seeded internal name survives, single-label names included (RT2, RT8).
  - The snapshot reproduces byte-identically from the stored object, and its sha256 and signature verify in the API and with `scripts/verify_report.py` offline.
  - Every citation resolves to an in-scope row whose `fields_sha256` matches at finalize time.
  - AI sections contain only supported claims and labelled hypotheses.
  - "Which report versions and AI outputs cite this row" works.
- **Rendering:**
  - PDF (PDF/A-3a, tagged, with the snapshot, manifest and signature embedded, TLP in the header and footer of every page), HTML and Markdown render in the report-worker.
  - The hostile fixture renders with every payload as visible text, no fetch attempted, no script and no style escape.
  - Rendering twice with the same image gives byte-identical PDFs (RT17).
  - A snapshot at the render budget renders within the sandbox limits (RT1).
  - The renderer has no egress or DB, and its render subprocess cannot open an inet, netlink or packet socket or an io_uring.
- **Security:**
  - Every new route is in the IDOR enumerator, every new table in RLS coverage, and the append-only tables refuse UPDATE and DELETE even for the owner.
  - Downloads are audited and served with attachment, CSP sandbox and nosniff.
  - The signing key exists only in the api role, and prod refuses the dev key.
- **Metric (§14), recorded in `plans/reports/report-metric-YYMMDD.md` and TESTING.md:** report citation resolution accuracy = 1.0, render success rate, render latency p50/p95 per format, deterministic-render rate = 1.0, hostile-fixture escapes = 0, and veraPDF PDF/A-3a result (local, recorded).
- **Gate:** `pnpm verify:prod` green. The e2e covers case → notes → collection → ATT&CK → report → finalize → PDF download → viewer (signature valid). The prod e2e asserts the report-worker runs with `ENV=prod`, the prod image and no dev signing key.
- **Docs:** new `docs/REPORTS.md`. ARCHITECTURE, DATABASE, API, THREAT_MODEL (renderer, TLP, signing), AI_ANALYST and THREAT_INTEL (policy), DEPLOYMENT (bucket, keys), TESTING, ROADMAP, PRD and README are updated.

## Out of scope

- **Signing and archival extras:** PAdES / pyHanko PDF signatures, RFC 3161 timestamps, KMS/HSM key custody and per-user signing keys.
- **DOCX export** (RT12): deferred to a later milestone, which would add a deterministic zip writer and its own checks.
- **Report editing:** a WYSIWYG or rich-text editor, Markdown in analyst text, custom templates per org, images or charts in reports (the deny-all fetcher stays strict; a later milestone can add bundled SVG charts generated by trusted code).
- **Sharing and collaboration:**
  - sharing reports outside the platform (public links, email);
  - report approval workflows, multi-signer reviews, and comments on reports;
  - STIX / TAXII publishing, MISP push of collections, and IOC collections across cases (org-wide watchlists).
- **AI writing the report:** AI never drafts analyst sections in M6. AI content enters only as selected, verified M5 runs.
- **Data lifecycle:** retention and purge of reports or notes; investigations stay archived, not deleted.
- **Not required by the gate:** veraPDF in CI (it is a local, recorded check), and PDF/UA-1 conformance claims (only PDF/A-3a is claimed).

## Open risks

- **A compromised renderer** (a parser bug in Pango, HarfBuzz, fontTools or pydyf triggered by evidence text) controls renditions but not the signed snapshot.
  - Bounded by: no egress or DB, a broker user confined to `report*`, presigned single-object URLs, the seccomp socket deny, rlimits, and the API re-hash.
  - Residual: a misleading PDF. Verification against the embedded, signed snapshot is documented.
- **WeasyPrint CVE cadence:** three fetcher or CSS-injection CVEs in 2025–26. Pinned below the next major; the deny-all fetcher and constant options cover the known classes. A new major is a parent decision.
- **API-held signing key:** an API compromise can sign forged versions. This is the same trust level as the DB writer. KMS later.
- **Pseudonymization in `external` reports** is pattern-based (the M5 residual), narrowed by the whole-token second pass (RT8). The UI shows a preview, and the analyst confirms the external review and the distribution. The report-level map is not stored (RT29).
- **Render budget calibration (RT1):** the initial `REPORT_MAX_RENDER_UNITS` is an estimate until phase 4 measures it. A low value refuses large reports (the user narrows the selection); a high value lets renders fail with `oom`.
- **Policy windows (RT20):** manual TI lookups are not case-scoped, and a provider call already in flight when a flag flips completes.
- **Lane memory:** `report-worker-test` (1 GB) plus two API lanes within `LANE_SLOTS=3` fits the M5 budget (5–8 GB free) only if the analyzers stay stopped.
- **Contract drift:** the frontend builds against stubs. Any schema change after phase 1 is a parent broadcast; the merge step checks for drift.
