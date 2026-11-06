---
phase: 4
title: "Isolated report renderer worker"
status: completed
priority: P1
effort: "16h"
dependencies: [1]
---

# Phase 4: Isolated report renderer worker (group B, 2c, lane 4 + report-worker-test)

## Overview
The `report-worker` turns a signed snapshot into PDF/A-3a, HTML and Markdown. DOCX is deferred (RT12). It sits in the untrusted zone and is hardened like the M2/M3 analyzers, plus a sandboxed render subprocess that cannot open network sockets.

This phase also owns the trusted side of the pipeline:
- render creation and dispatch;
- the ingest of `report.rendered`;
- the render routes and downloads;
- the reaper.

**Owns:**
- `apps/workers/report/**`: Dockerfile, `report_worker/{app,tasks,fetch,sandbox,render_html,render_pdf,render_md,checks,text}.py`, `templates/incident_v1/*.html.j2`, `assets/report.css`, `assets/fonts.conf`, and `tests/**`. The seccomp filter and the rlimits come from the worker-kit extension of phase 1 (`Rlimits`, `deny_network(extra_domains, deny_io_uring)`); this phase never edits `packages/py-worker-kit` (RT3);
- `app/modules/reports/{dispatch,render_ingest,router_renders}.py` (after the stubs);
- `app/workers/reaper.py` (`reap_report_renders`);
- `tests/security/idor_cases_renders.py`;
- `tests/integration/test_report_{renders,render_ingest,render_reaper}.py`.

## Requirements
- **Trusted side:**
  - **`dispatch.create_render(session, org_id, user_id, version, fmt)`:**
    - Dedupe: an existing non-failed render of the same (version, format, `RENDERER_VERSION`) is returned.
    - Caps: `REPORT_ACTIVE_RENDERS_PER_ORG` (2) / `GLOBAL` (4 per replica) under advisory locks (the M4/M5 pattern) → `409 render_busy` (RT5).
    - It inserts `report_renders` (`queued`, `token_sha256` of a fresh random token) and `report_render_index` (deadline `REPORT_RENDER_DEADLINE_S`, 600 s: with the global cap at 4 and at most about 100 s per render, the last queued render still finishes in time, RT5).
  - **`dispatch_render(render_ids)`** builds `ReportRenderMessageV1`:
    - a presigned GET for the snapshot object at its exact version id (TTL = the deadline);
    - `snapshot_sha256` and `snapshot_bytes` (for `transfer.download`, RT21);
    - `manifest_b64`, `signature` and `kid` (the renderer embeds them; it never signs anything), and `finalized_at` (the fixed document and attachment dates, RT17);
    - a presigned POST for `reports/{org}/{rid}/{v}/{render_id}.{ext}` with a `content-length-range` of 1 … `REPORT_MAX_ARTIFACT_BYTES` and the content type fixed per format;
    - the token and the deadline.

    It then sends `report.render`. A publish failure leaves the render `queued`, and the reaper re-dispatches it.
  - **`render_ingest.handle_rendered(msg)`** (ingest-worker, trusted; allowlisted in the tenant-session guard):
    1. Find the org through `report_render_index`, then check the token hash and the `running/queued` state.
    2. On `succeeded`: stat the uploaded object, **re-hash it** and compare against the message's `sha256` and `bytes` (`invalid_output` on mismatch). Check the magic (`%PDF-`, UTF-8 for MD/HTML). Set the per-object GOVERNANCE retention on that exact version (RT6), then set `succeeded` with sha256, bytes, pages, `renderer_version` and the object version id. Ingest never parses the artifact (RT27).
    3. On `failed`: store the typed `error_code`.
    4. Write the audit `report.rendered` / `report.render_failed` (format, code).
  - **`reaper.reap_report_renders()`:** re-dispatches `queued` renders that were never dispatched, and fails renders past their deadline with `timeout`. It returns a count.
  - **Routes** (frozen in phase 1):
    - `POST /reports/{rid}/versions/{v}/renders` (`investigation.write`; 20 per user per 10 min): `{format}` → 202, or 200 when deduplicated;
    - `GET /reports/{rid}/versions/{v}/renders` (`investigation.read`);
    - `GET /report-renders/{render_id}` (`investigation.read`);
    - `GET /report-renders/{render_id}/download` (`evidence.read`): streamed from the exact object version and re-hashed while streaming (`409 integrity_failed` and an audit on mismatch). It is an attachment with an RFC 5987 filename that carries the TLP (`CASE-00012_v2_TLP-AMBER.pdf`), `nosniff`, `no-store`, and `Content-Security-Policy: sandbox; default-src 'none'; style-src 'unsafe-inline'` for HTML (`sandbox` for all). Audited as `report.downloaded` (format, version, TLP).
- **Worker side** (`apps/workers/report`):
  - **The task** `report.render`:
    1. Validate the message (`ReportRenderMessageV1`) and the deadline.
    2. `cyberlab_worker.sandbox.prepare` on `/work`. It runs `reset` first, which kills any uid-10003 process left behind and removes earlier files (RT4).
    3. Download the snapshot through `cyberlab_worker.transfer.download` (`snapshot_bytes`, size cap, sha256 check → `snapshot_mismatch`).
    4. Validate it as `ReportSnapshot`.
    5. Write the input and `manifest.json` / `manifest.sig.json` into the job's root-owned, read-only `input/` dir.
    6. Run the render subprocess.
    7. Check the output (`checks.py`).
    8. Upload through the presigned POST.
    9. Send `ReportRenderedV1` to `ingest`, then `sandbox.cleanup`.

    Every failure maps to a typed `error_code`, and nothing from the exception text is sent.
  - **Sandbox** (`sandbox.py`, calling `cyberlab_worker.sandbox.run_tool` with the phase-1 extensions, RT3, RT4):
    - The subprocess runs `python -I -B -m report_worker.render <format> <in> <out>` as uid 10003.
      - `-I` gives isolated mode: no `PYTHON*` env, and no cwd or user site on `sys.path`.
      - **Not `-S`**: it would drop the venv's site-packages, and nothing would import.
    - The env holds only `PATH`, `LANG=C.UTF-8`, `FONTCONFIG_FILE=/app/assets/fonts.conf`, `HOME` / `TMPDIR` = the job's `out/` dir, and `MALLOC_ARENA_MAX=2`, which keeps glibc arenas under `RLIMIT_AS`.
    - cwd is a root-owned read-only dir, the worker-kit pattern for Python probes.
    - `Rlimits(as_bytes=768 MiB, cpu_s=90, fsize_bytes=REPORT_MAX_ARTIFACT_BYTES, nofile=64, nproc=16)`.
    - Wall timeout 100 s (kill the process group).
    - Seccomp: `deny_network(extra_domains=(AF_NETLINK,), deny_io_uring=True)`, which denies `AF_INET`, `AF_INET6`, `AF_PACKET`, `AF_NETLINK` and `io_uring_setup` with **`EACCES`**. `AF_UNIX` stays allowed; whether fontconfig uses it is checked and recorded.
    - The result codes map to `timeout`, `oom` (MemoryError or SIGKILL under the rlimit) and `renderer_error`.
  - **HTML** (`render_html.py`):
    - `jinja2.sandbox.SandboxedEnvironment(loader=FileSystemLoader("/app/templates"), autoescape=True, undefined=StrictUndefined, trim_blocks=True)`.
    - Filters: `vis` (the bidi, zero-width, control, tag and other `Cf` characters made visible as `⟨U+XXXX⟩`, read from the materialized `vis_rules.json`, RT24), `ts` (UTC), `tlp_label` and `sev_class` (fixed mapping). There is no `defang` filter: the snapshot already holds the defanged form (RT24).
    - **No `|safe`, `Markup` or `autoescape false`** (`tests/test_template_lint.py` greps the templates and the Python code).
    - The template is `incident_v1/report.html.j2` with partials per section, `<html lang="en">`, `<title>`, real `h1`–`h3`, `<table>` with `<th scope>`, and DOM order equal to reading order.
    - Citations render as superscript `[C12]`, which is an in-document anchor (`href="#c12"`, built from integers only).
    - The appendix lists each citation with its kind, ids, `fields_sha256`, the copied fields as escaped text, and the platform path as text plus an `<a href>`.
      - The link is built only from `PUBLIC_BASE_URL` (passed by the API in the snapshot's `report.base_url`, validated by the contract as an https or localhost URL) and UUIDs.
      - `external` snapshots have no `base_url` and no paths, so no link is emitted (RT8).
      - The appendix uses block layout, not tables, which keeps WeasyPrint's layout cost linear (RT1).
    - **Cover:**
      - TLP banner (FIRST colours on black) with the FIRST one-line definition of the label (RT23);
      - case ref, title, version, finalized time, short sha256, profile, distribution;
      - the document-control table of prior versions and change notes (RT23).

      Then a table of contents, the analyst sections, and each data section with its totals ("showing 500 of 3 412").
    - **AI sections** carry a boxed "AI-generated interpretation: observations to verify, not verdicts" with the model and `prompt_version`. Flags are shown inline on each claim (RT15).
    - **HTML head:** `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">` (RT19).
  - **CSS** (`assets/report.css`, trusted and constant):
    - A4, `@page` margin boxes `@top-right` and `@bottom-right` showing the TLP label ≥ 12 pt, `@bottom-left` showing "CASE-… v2 sha256:abcd1234…", and `@bottom-center` with page counters;
    - `overflow-wrap: anywhere` on code and IOC cells;
    - fixed classes for severity and TLP;
    - **no `url()`, `@import` or `@font-face url()` at all**. Fonts come from fontconfig (`local()` / family names of the bundled Noto set). The file is read once at import and passed as `CSS(string=…)` (RT16).
  - **PDF** (`render_pdf.py`):
    - `weasyprint.HTML(string=html, base_url=None, url_fetcher=DenyAllFetcher()).write_pdf(target, stylesheets=[REPORT_CSS], pdf_variant="pdf/a-3a", pdf_identifier=<sha256 bytes[:16]>, attachments=[…], presentational_hints=False, uncompressed_pdf=False, custom_metadata=False)`.
      - `REPORT_CSS` is the constant `CSS(string=…, url_fetcher=DenyAllFetcher())`.
      - pdf/a-3a forces tags and the sRGB `output_intent` (the 69.0 rename of `srgb`, RT17).
    - The attachments are `Attachment(string=<bytes>, name=…, relationship="Source", created=finalized_at, modified=finalized_at)` for `snapshot.json`, `manifest.json` and `manifest.sig.json`.
      - They are passed as bytes, never as file names, which would go through the fetcher (RT16).
      - The dates are fixed, because they default to now (RT17).
    - The `dcterms.created` / `dcterms.modified` meta come from `finalized_at`; without them WeasyPrint omits the dates. Output is byte-identical **for the same image and `RENDERER_VERSION`** (RT17).
    - `DenyAllFetcher(URLFetcher)` overrides `fetch` to raise `FatalURLFetchingError` for **every** URL: `data:`, `file:`, `http(s):` and relative URLs alike. In WeasyPrint 70, `data:` URIs also go through the fetcher (RT16). A blocked fetch is reported as `fetch_blocked`. The hostile fixture never makes one, because the templates emit no URLs; the tests inject them directly to prove the guard.
    - After rendering: count the pages (≤ `REPORT_MAX_PAGES` 300 → else `too_many_pages`) and check the size (≤ 32 MiB).
  - **HTML artifact:** the same HTML with the CSS inlined, the fonts omitted and the meta CSP in the head (RT19).
  - **Markdown** (`render_md.py`):
    - our own escaper: backslash-escape ASCII punctuation in text;
    - evidence values go in fenced code spans or blocks with a fence longer than any backtick run;
    - `|` escaped in tables, and newlines inside a table cell replaced by ` ⏎ ` so a value cannot end its row (RT19);
    - leading `#`, `>`, `-`, `+`, `=` and digit-dot neutralized;
    - no raw HTML and no links except `#cN` anchors and the platform paths as text;
    - a TLP line at the top and the bottom.
  - **`RENDERER_VERSION`** = `report-worker/<semver>+weasyprint-<ver>+template-incident_v1.<n>`, sent on every result.

## Implementation Steps
1. The trusted side first (lane 4):
   - `create_render`, `dispatch_render`, routes, downloads, ingest, reaper;
   - `test_report_renders.py`: dedupe, caps, permissions, download headers and audit, an integrity mismatch → 409;
   - `test_report_render_ingest.py`: wrong token, other org, a hash or size mismatch, bad magic, a final state is immutable;
   - `test_report_render_reaper.py`.

   A fake renderer posts fixture artifacts through the presigned POST from inside api-test.
2. Worker skeleton → task flow with a fake render subprocess; `tests/test_task.py` (snapshot mismatch, deadline passed, typed errors, no exception text in results).
3. Sandbox and seccomp socket deny; `tests/test_sandbox.py`:
   - the subprocess gets `EACCES` from `socket(AF_INET)`, `socket(AF_NETLINK)` and `io_uring_setup`, and cannot resolve or connect to `redis-broker` / `minio`;
   - `python -I -B` imports `weasyprint` and `report_worker` from the venv (RT4);
   - a background process left by a render is killed by `reset` before the next one;
   - the env is empty of `BROKER_URL`;
   - `RLIMIT_AS` turns a 2 GB allocation into `oom`;
   - an infinite loop gives `timeout`.
4. HTML templates and filters; `tests/test_render_html.py`: the golden snapshot renders every section; the hostile snapshot's payloads appear escaped as text (no `<img`, `<script`, `</style>` or `url(` from data in the output; U+202E visible as `⟨U+202E⟩`); `tests/test_template_lint.py`.
5. PDF:
   - `tests/test_render_pdf.py`: `%PDF-`, PDF/A-3a markers, three embedded attachments whose bytes equal the inputs, TLP text on every page (extracted per page with `pypdf` in tests only), the page cap;
   - **rendering twice → identical bytes**;
   - `DenyAllFetcher` refuses `http:`, `https:`, `data:` (including a 64 MiB `data:` URI, refused before decoding), `file:///etc/passwd`, `file:///app/assets/…` and relative URLs, through `HTML`, `CSS`, `@import`, `@font-face url()` and `<img>` (RT16);
   - the image has no `gs` binary (RT16).
6. Markdown: `tests/test_render_md.py` (escaper property tests: no rendered link, image or HTML in CommonMark **and GFM** output via `markdown-it-py` with linkify in tests only; newlines in table cells; `&#x202E;` entities stay inert).
7. **Heavy step (the parent runs it alone):** `test_report_renders.py::test_end_to_end_pdf` with `report-worker-test` up. API finalize (with a seeded version) → render → ingest → `succeeded` → download re-hash.
8. `idor_cases_renders.py`: cases and the victim extender (a render). Empty `PENDING_ROUTES`.
9. **Render budget calibration (RT1):** render a generated worst-case snapshot at `REPORT_MAX_RENDER_UNITS` (citations, IOCs and timeline at their caps with 4 096-character fields) in `report-worker-test`. Record the peak RSS, CPU seconds, pages and bytes, and propose the budget value that keeps the peak under about 600 MiB and 60 s CPU. The parent sets it before the merge. Also record the image size, the p50/p95 render times for the golden snapshot, and fontconfig's socket needs.

## Success Criteria
- [x] The render subprocess cannot open inet, netlink or packet sockets or an io_uring, gets no broker URL, and is bounded in memory, CPU and time with typed failures. The worker uses prefork with one task per child, and `reset` runs before every render. — `apps/workers/report/tests/test_sandbox.py::test_every_socket_family_but_unix_is_denied_with_eacces`, `test_io_uring_setup_is_denied_with_eacces`, `test_the_environment_holds_no_broker_url`, `test_the_broker_and_minio_cannot_be_resolved_or_reached`, `test_a_2_gb_allocation_is_oom`, `test_the_cpu_limit_is_a_timeout`, `test_an_infinite_loop_is_a_timeout`, `test_writing_past_the_artifact_cap_is_too_large`, `test_a_background_process_is_killed_by_reset_before_the_next_render`; `test_task.py::test_reset_kills_leftovers_before_a_render`, `test_render_failures_are_typed_and_carry_no_text`; `test_skeleton.py::test_celery_runs_prefork_one_task_per_child_with_limits` (319f04d).
- [x] A snapshot at the calibrated render budget renders within the sandbox limits (RT1). — `test_render_budget.py::test_a_snapshot_at_the_budget_renders_within_the_sandbox` at 450 000 units: worst shape peaks at 594 MiB RSS of the 768 MiB `RLIMIT_AS` and at most 214 pages (cap 300). The opt-in calibration sweep is `test_calibrate` (`REPORT_CALIBRATE=1`) (319f04d).
- [x] The hostile snapshot renders in PDF, HTML and Markdown with every payload as inert visible text. No fetch is attempted, and the fetcher guard refuses every URL (tested directly). — `test_render_html.py::test_hostile_payloads_are_inert_visible_text`, `test_only_known_tags_attributes_classes_and_links`; `test_render_md.py::test_the_hostile_document_has_no_links_images_or_html`, `test_entities_stay_inert`; `test_render_pdf.py::test_the_hostile_snapshot_renders_reproducibly`, `test_the_fetcher_refuses_every_url`, `test_every_resource_kind_goes_to_the_fetcher_and_fails_the_render`, `test_the_template_output_makes_no_fetch`, `test_a_64_mib_data_uri_is_refused_without_decoding`; `test_template_lint.py` (6) (319f04d).
- [x] The PDF is PDF/A-3a, carries the snapshot, manifest and signature as attachments that match the inputs byte for byte, shows the TLP in the header and footer of every page, and renders byte-identically twice with the same image. — `test_render_pdf.py::test_the_pdf_is_pdf_a_3a` (a structural check with pypdf: the PDF/A identification and tags), `test_the_attachments_are_the_inputs_byte_for_byte`, `test_the_tlp_is_in_the_header_and_footer_of_every_page`, `test_every_tlp_label_reaches_the_margins`, `test_rendering_twice_gives_identical_bytes`; `test_task.py::test_the_embedded_inputs_are_the_signed_bytes` (319f04d). veraPDF was **not run** (a local, non-gating check, open in phase 9).
- [x] Ingest re-hashes every artifact and refuses mismatched, oversized or mis-typed outputs. Downloads are audited, re-hashed and served as attachments with CSP sandbox. — `integration/test_report_render_ingest.py::test_mismatched_artifacts_fail_with_invalid_output`, `test_a_verified_artifact_succeeds_with_retention_and_audit`, `test_text_formats_succeed_when_utf8`, `test_a_wrong_token_changes_nothing`, `test_ingest_reads_the_org_from_the_index_only`; worker side `test_task.py::test_invalid_outputs_are_refused`, `test_too_many_reported_pages_are_refused`; `test_report_renders.py::test_a_download_is_an_audited_sandboxed_attachment`, `test_a_tampered_artifact_is_refused_and_audited` (319f04d).
- [x] Dedupe, caps, the reaper and the deadline work. IDOR cases are complete and `PENDING_ROUTES` is empty. — `test_report_renders.py::test_the_same_format_is_deduplicated`, `test_the_per_org_cap_answers_render_busy`, `test_the_global_cap_answers_render_busy`, `test_a_lost_publish_leaves_the_render_queued_for_the_reaper`, `test_render_requests_are_rate_limited`; `test_report_render_reaper.py` (5: deadline `timeout`, redispatch with a valid token, `RENDER_MAX_ATTEMPTS = 3`); `security/idor_cases_renders.py` `PENDING_ROUTES = frozenset()` (319f04d). The heavy `test_end_to_end_pdf` runs in the gate (`REPORT_E2E=1`, pending gate).

## Risk Assessment
- **Fontconfig or Pango need syscalls** that the seccomp variant blocks, or need a writable cache. Pre-build the font cache in the image (`fc-cache` at build time), point the cache dir at tmpfs, and record any syscall added to the allow-list.
- **Reproducible output** may break on WeasyPrint upgrades or Debian font / Pango updates (font subsetting order, ids). Pin the version, record it in `RENDERER_VERSION`, claim determinism per image only, and keep the render-twice test in CI (RT17).
- **PDF/A-3a validation** is not proven without veraPDF. It is a local check recorded by phase 9 and not a gate.
- **Large reports:** WeasyPrint keeps the whole document in memory (upstream reports about 2.6–3 GB for 1 500 pages). The render budget, checked at finalize, keeps signed versions renderable (RT1). If calibration shows the budget is too small for real cases, the parent may raise `mem_limit` and `RLIMIT_AS` together (host RAM permitting) rather than the budget alone. On `oom`, the UI suggests narrowing the selection.

## Implementation Notes (2026-11-06)
- **Commit:** 319f04d (phases 2–8 together).
- **Lane 4 in the main tree:**
  - API tests ran through `scripts/lane-test.sh 4`.
  - Renderer tests ran through `scripts/lane-test.sh 4 --service report-worker-test pytest -q tests/` (same slot lock).
  - The worktrees were blocked by the permission system (phase-1 notes).
- **Renderer** (`apps/workers/report/report_worker/`):
  - Modules: `tasks.py`, `checks.py`, `sandbox.py`, `render.py`, `render_pdf.py`, `render_html.py`, `render_md.py`, `fetch.py`, `text.py`.
  - Templates: 13 Jinja2 partials in `templates/incident_v1/`.
  - Stylesheet: the constant `assets/report.css`.
  - WeasyPrint 70.0, without Ghostscript (`test_the_image_has_no_ghostscript`).
- **Sandbox:**
  - `python -I -B -m report_worker.render` runs as uid **10004** (review L6; the plan said 10003).
  - The seccomp filter is the `unix_only` allowlist (review L5): every socket family but `AF_UNIX` fails with `EACCES`, and so does io_uring.
  - `Rlimits(as=768 MiB, cpu=90 s, fsize=32 MiB artifact cap, nofile=64, nproc=16)`.
  - Wall timeout 100 s; Celery soft and hard limits 90 / 120 s.
  - The environment has no broker URL.
  - The font cache is prebuilt and read-only.
- **Worker:**
  - Celery prefork, `concurrency=1`, `max_tasks_per_child=1`, `prefetch=1`.
  - `sandbox.prepare` resets before each render: it kills every uid-10004 leftover.
  - The inputs are root-owned and read-only.
  - The snapshot sha256 and the manifest are checked before rendering. An unreachable snapshot counts as a mismatch.
  - Failures are typed codes only (`timeout`, `oom`, `too_large`, `fetch_blocked`, …) and carry no text.
- **Fetcher and templates:**
  - The deny-all `url_fetcher` refuses every URL, including `data:` URIs: a 64 MiB one is refused without decoding.
  - Relative URLs are never resolved.
  - The constant CSS was built with the deny-all fetcher.
  - The sandboxed Jinja2 environment autoescapes, uses `StrictUndefined` and has no escape hatch (`test_template_lint.py`).
  - Classes come only from fixed filters.
  - Hrefs are anchors or platform links built from UUIDs.
- **Formats:**
  - **PDF/A-3a:** tagged, `Lang=en`, sRGB output intent. `snapshot.json`, `manifest.json` and `manifest.sig.json` are embedded byte for byte. The TLP label is in the header and footer of every page. Dates come only from `finalized_at`, which makes the output reproducible.
  - **HTML:** inlines exactly the constant CSS plus a meta CSP.
  - **Markdown:** escapes everything. Code fences are longer than any backtick run, and table cells cannot break their row.
- **API side** (`reports/dispatch.py` +314, `render_ingest.py` +259, `router_renders.py` +227, `workers/reaper.py` +137):
  - Dedupe uses the partial unique index per (version, format, renderer_version).
  - Active-render caps of 2 per org and 4 globally answer `409 render_busy`; renders are limited to 20 per user per 10 min.
  - The publish happens after the commit.
  - Ingest reads the org from `report_render_index` only, re-hashes and checks size and type, then sets retention.
  - The reaper fails renders past the deadline (600 s) with `timeout` and redispatches a lost publish at most 3 times. `test_tenant_session_guard.PENDING_ALLOWED` is now empty.
- **Calibration (RT1):**
  - Worst shapes at 450 000 units: peak 594 MiB RSS of 768 MiB (target ≤ 600), at most 214 pages, CPU under the 60 s target.
  - Golden PDF p50 / p95: 3.9 s.
  - `REPORT_DEFAULT_MAX_RENDER_UNITS` and `CALIBRATED_RENDER_UNITS` are both set to 450 000 (750 000 was the phase-1 estimate).
- **Tests:**
  - Renderer suite: 1857 passed in `report-worker-test`.
  - API: `test_report_{renders,render_ingest,render_reaper}.py`.
  - Phase 9 added `test_report_pipeline.py` and put `test_end_to_end_pdf` in the gate (`REPORT_E2E=1`); that run is pending gate.
- **Not done:**
  - veraPDF validation (local only, not run);
  - CJK glyphs: `fonts-noto-core` has no CJK coverage; documented in REPORTS.md.
- **Closure (2026-11-06):** `test_report_pipeline.py` under `REPORT_E2E=1` ran in gate run vp8 (API 4915 passed), and the renderer suite in `test:workers`; the gate passed in segments, not in one `pnpm verify:prod` run (see the plan's Closure).
