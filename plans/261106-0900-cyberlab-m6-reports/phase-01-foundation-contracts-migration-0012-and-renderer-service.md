---
phase: 1
title: "Foundation contracts migration 0012 and renderer service"
status: pending
priority: P1
effort: "22h"
dependencies: []
---

# Phase 1: Foundation contracts migration 0012 and renderer service (group A)

## Overview
One agent lays the frozen foundations for six parallel lanes:
- migration 0012 and the models;
- the shared snapshot contract `cyberlab.report.v1` and the render messages in `packages/py-jobs`;
- every new route as a **501 stub** with its frozen request and response schemas, followed by one `pnpm gen:contracts` run, so the frontend phases start on real types;
- the share-policy function and its call sites in the M4/M5 paths. It is implemented here because those files belong to no group-B phase;
- the Ed25519 signing core and its dev keys;
- the `reports` and `reports-test` MinIO buckets (RT6);
- the `report-worker` image skeleton, compose services, broker ACL user and network placement;
- the worker-kit sandbox extension, `tenant_session(snapshot_read=…)`, the timeline signature change and the cross-phase stubs (RT3, RT10, RT11, RT14);
- test helpers, the hostile and golden fixtures, the IDOR module split and the empty routers.

Red-team changes applied here: RT1, RT3–RT14, RT16–RT24 (see plan.md).

After this phase the stack runs as before:
- the new routes answer `501 not_implemented`;
- the report-worker starts and fails any `report.render` with `not_implemented`;
- the policy check is live but allows everything for existing cases: TLP defaults to `amber` and no flags are set.

**Everything listed under "Frozen interfaces" in plan.md is frozen at the end of this phase.**

## Requirements
- **Pre-flight:**
  - Confirm that M5 is merged and its gate is green.
  - Confirm the alembic head is `0011`; otherwise number the migration head + 1 and tell the parent.
  - Create branch `feat/m6-reports` from the M5 merge.
  - Re-verify on PyPI and OSV: `weasyprint` (≥ 70.0 and the CVE ids CVE-2025-68616, CVE-2026-49452, CVE-2026-55073, CVE-2026-106443), `fonttools` (≥ 4.60.2, CVE-2025-66034), `jinja2` (≥ 3.1.6) and `pydyf`. The red-team pass checked these on 2026-11-06 (RT16). Record the resolved versions in the phase notes. `python-docx` is not used: DOCX is deferred (RT12).
- **Migration `0012_reports_case_mgmt.py`** (the conventions of 0011: `TENANT_TABLES`, `APPEND_ONLY`, `GRANTS`, `UPDATE_COLUMNS`; FORCE RLS; the `tenant_isolation` policy; composite FKs with `UniqueConstraint(id, organization_id)` on parents; named `op.f("ck_…")` checks; `octet_length` caps; no DELETE grant):
  - **`investigations` gets new columns:**
    - `tlp text NOT NULL DEFAULT 'amber'`, checked against the five values;
    - `ai_excluded` and `ti_excluded`, both `bool NOT NULL DEFAULT false`;
    - existing rows are backfilled by the defaults.
  - **New tables:** `investigation_status_events`, `evidence_share_policies`, `analyst_notes`, `analyst_note_versions`, `ioc_collections`, `ioc_collection_items`, `case_attack_mappings`, `reports`, `report_versions`, `report_citations`, `report_renders` and `report_render_index`, exactly as in the plan.md data model table.
  - **Triggers:**
    - `analyst_note_guard`: `current_version` is monotonic, the delete fields are set once, and `investigation_id` / `created_by` are immutable;
    - `report_guard`: `revision` is +1 per update; `latest_version` is monotonic; `discarded` is allowed only while `latest_version = 0`; a discarded draft is final; identity columns are immutable;
    - `report_render_transition`: `queued → running | failed`, `running → succeeded | failed`; finals and identity are immutable;
    - `ioc_collection_item_guard`: `removed_*` is set once, and identity is immutable.
  - **`forbid_mutation`** on `investigation_status_events`, `analyst_note_versions`, `report_versions` and `report_citations`.
  - **Checks:**
    - `report_versions`: `snapshot_sha256 ~ '^[0-9a-f]{64}$'`, `manifest` ≤ 4 KiB, signature base64 of 64 bytes, `kid` pattern;
    - `reports.draft` ≤ 1 MiB (RT9); `report_versions.change_note` ≤ 500 characters, no NUL (RT23);
    - `analyst_note_versions.body`: `char_length` ≤ 20 000, and `refs` a JSON array of ≤ 20 entries;
    - `report_citations`: `ref_id` ≤ 64 and `cite_no` > 0;
    - `report_renders`: `format` ∈ {pdf, html, md} (RT12), `token_sha256` pattern.
  - **Indexes:**
    - `report_citations (organization_id, kind, ref_id)`;
    - `ioc_collection_items (organization_id, ioc_key)`;
    - `analyst_notes (investigation_id, created_at)`;
    - `investigation_status_events (investigation_id, occurred_at)`;
    - `report_render_index (status, deadline_at)`.
  - **Upgrade and downgrade** are both tested.
  - **`AiErrorCode` gains `policy_blocked`.** If `ai_runs.error_code` has a check constraint, 0012 extends it. The TI run error codes gain `policy_blocked` in the same way.
- **Models:**
  - `investigations/models.py` gets the columns plus `InvestigationStatusEvent` and `EvidenceSharePolicy`;
  - new `notes/models.py`, `ioc_collections/models.py`, `case_attack/models.py` and `reports/models.py`;
  - all registered in `app/models.py`.
- **Snapshot contract** `packages/py-jobs/src/cyberlab_jobs/report.py`:
  - `REPORT_SCHEMA`, `TLP` (StrEnum `clear/green/amber/amber_strict/red`), `TLP_ORDER`, `TLP_LABELS` (`TLP:AMBER+STRICT`, …), `TLP_COLOURS` (#FF2B2B / #FFC000 / #33FF00 / #FFFFFF on #000000), `TLP_DEFINITIONS` (the FIRST one-line definitions, RT23), `Profile` (`internal/external`).
  - `STIX_TLP_MARKINGS` (RT18): the five OASIS TLP 2.0 marking-definition objects (ids CLEAR `marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487`, GREEN `…--bab4a63c-aed9-4cf5-a766-dfca5abac2bb`, AMBER `…--55d920b0-5e8b-4f79-9ee9-91f868d9b421`, AMBER+STRICT `…--939a9414-2ddd-4d32-a0cd-375ea402b003`, RED `…--e828b379-4e03-4974-9ac4-e53a884c97c1`; extension `extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d`, `created` 2022-10-01), copied verbatim from `oasis-open/cti-stix-common-objects`.
  - The snapshot models (see plan.md frozen list 2):
    - evidence-derived text is `BoundedText` (≤ 4 096, truncated with the marker); analyst-authored text (sections, notes, rationale, distribution, status reasons) is `AnalystText` (≤ 20 000, refused above, never truncated) (RT9); both reject NUL;
    - every list carries its cap and a `total` count; `extra="forbid"`; `frozen=True`;
    - `document_control: list[DocumentControlItem{version, finalized_at, snapshot_sha256_short, change_note}]` for the prior versions (RT23);
    - `render_units(snapshot) -> int` (rendered text characters plus a fixed weight per table row and citation), with a unit test that pins its value on the golden snapshot (RT1).
  - `canonical_json(obj) -> bytes`: sorted keys, `separators=(",", ":")`, `ensure_ascii=False`, UTF-8, no floats (scores and entropy are fixed-point strings), RFC 3339 `Z` timestamps.
  - `Manifest` and `manifest_bytes(manifest) -> bytes`.
  - `ReportRenderMessageV1` (with `manifest_b64`, `signature` and `kid`, which the renderer only embeds; `snapshot_bytes` for `transfer.download`, RT21; `finalized_at` for the fixed PDF and attachment dates, RT17), `ReportRenderedV1`, `RENDER_FORMATS` (`pdf`, `html`, `md`), `RENDER_ERROR_CODES` (`not_implemented`, `snapshot_mismatch`, `fetch_blocked`, `timeout`, `oom`, `too_large`, `too_many_pages`, `invalid_output`, `renderer_error`).
  - `tasks.py`: `REPORT_RENDER = "report.render"` (queue `report`) and `REPORT_RENDERED = "report.rendered"` (queue `ingest`). `Queues.report`.
  - Tests: round-trip, canonical bytes stable across key order, caps, NUL refusal, a worst-case size near 8 MiB, `AnalystText` not truncated, the `render_units` pin.
- **Policy** (`investigations/policy.py`, implemented):
  - `load_policy` resolves the case flags and TLP, plus the evidence share-policy rows of the evidence behind the given jobs. TLP:RED blocks both AI and TI. It returns `SharePolicy{ai_blocked, ti_blocked, reasons: list[str], excluded_evidence_ids}`.
  - **Call sites** (at the service choke points, not the routers, RT20):
    - `ai/service_runs.request_run` and `preview`, on run creation and preview (`409 policy_blocked`, `detail.reason`);
    - `ai/context/builder.py`, in the incident job selection. Excluded evidence is skipped and counted in `context_stats.policy_excluded`:
      - an additive field on `ai/contracts.py: ContextStats` (default 0), documented as a frozen-contract change of M5 approved by the parent;
      - **stored only, never rendered into the prompt**, so the pinned prompt digests and `prompt_version` stay unchanged. The M5 prompt-pin test must stay green;
    - the analyst-worker before **every** provider request, including `count_tokens` (`failed / policy_blocked`, no call);
    - `threat_intel/service_runs._request` for job-scope enrichments, and the enrich-worker before each provider slice (`failed / policy_blocked`). Manual lookups (`scope="manual"`) have no case and stay unchecked (documented residual).
  - Tests: unit tests for the resolution, and one integration test per call site with ai-mock / ti-mock call counters at 0.
- **Signing** (`app/core/signing.py`, implemented):
  - Settings: `REPORT_SIGNING_KEYS_FILE` (api role only; every other role refuses it), `REPORT_SIGNING_PUBLIC_KEYS` (JSON kid → base64 raw public key) and `REPORT_SIGNING_ACTIVE_KID`.
  - Prod refuses the committed dev public key and any `dev-` kid. The `ingest`, `enrich`, `analyst` and report-worker envs carry no signing material. The private key is a compose secret mounted only on `api` (and on `api-test`, with test keys).
  - A dev pair `infra/reports/dev-signing-private.json` (kid `dev-report-1`) and `scripts/gen_report_signing_keys.py` (`--kid prod-report-YYYYMMDD`, `--out .secrets/report_signing_private.json`, `--add`).
  - Import guard (AST, all import forms): `core.signing.load_signing_keys` may be imported only from `reports/signing.py`.
  - Tests: sign/verify round trip, wrong kid, a flipped byte, reprs without key material.
- **Shared helper** `app/core/csv_safe.py` (implemented and frozen): `csv_safe(cell: str) -> str` (prefix `'` to cells whose first non-whitespace character is `= + - @ \t \r` or a full-width `＝ ＋ － ＠`, RT19; NUL removed) and `write_csv(rows, header_comment) -> Iterator[bytes]` (RFC 4180). It is used by phases 2 and 5; tests in `tests/unit/test_csv_safe.py`.
- **Settings** (`core/config.py`):
  - `REPORTS_BUCKET` (`reports`; `api-test` sets `${REPORTS_TEST_BUCKET}` = `reports-test`, RT6);
  - `REPORT_MAX_SNAPSHOT_BYTES` (8 MiB) and `REPORT_MAX_ARTIFACT_BYTES` (32 MiB);
  - `REPORT_MAX_RENDER_UNITS` and `REPORT_MAX_PAGES` (300) (RT1). The units start at an estimate for about 250 A4 pages (about 2 MB of renderer memory per page); phase 4 calibrates them and the parent sets the value;
  - `REPORT_RENDER_DEADLINE_S` (600) and `REPORT_RENDER_TIMEOUT_S` (120) (RT5);
  - `REPORT_RENDERS_PER_USER_10MIN` (20), `REPORT_FINALIZE_PER_USER_10MIN` (10), `REPORT_PREVIEW_PER_USER_10MIN` (30);
  - `REPORT_ACTIVE_RENDERS_PER_ORG` (2) and `REPORT_ACTIVE_RENDERS_GLOBAL` (4). One report-worker replica processes one render at a time, so the global cap scales with the replicas (documented, RT5);
  - `TIMELINE_EXPORT_MAX_ROWS` (50 000);
  - `PUBLIC_BASE_URL`: reuse it if one exists, otherwise add it, and refuse a plain `http://` value outside localhost in prod.
- **MinIO** (RT6):
  - **Buckets:** `infra/minio/init.sh` creates `reports` and `reports-test` with `mc mb --with-lock` (versioned) and **no default retention**, like the evidence bucket.
    - A default retention would make MinIO demand `Content-MD5` on the renderer's presigned POST.
    - An existing bucket without object lock is refused, as for evidence.
    - `reports-test` gets a lifecycle rule (`infra/minio/reports-test-lifecycle.json`) that expires noncurrent versions.
  - **Retention** is per object: GOVERNANCE for `EVIDENCE_LOCK_DAYS`. The API sets it on the snapshot (`storage.set_retention`), and the ingest-worker sets it on each artifact after its re-hash.
  - **Policy:** the api and ingest processes share the `cyberlab-api` MinIO user. `api-policy.template.json` gains:
    - on `reports/*` and `reports-test/*`: `GetObject`, `GetObjectVersion`, `PutObject`, `PutObjectRetention` and `GetObjectRetention`;
    - on the buckets: `ListBucket`, `ListBucketVersions` and `GetBucketObjectLockConfiguration`;
    - **no** `DeleteObject` or `DeleteObjectVersion`.
  - The report-worker has no MinIO credentials (presigned URLs only).
- **Compose:**
  - **Services:** an `x-report-worker` anchor cloned from the static-worker anchor (a root process with `cap_add: [SETUID, SETGID, KILL, CHOWN, DAC_OVERRIDE, FOWNER]`, RT3), with service `report-worker` (dev) and `report-worker-test` (profile `test`; broker db `${TEST_BROKER_DB:-1}`, queue prefix `test.`).
  - **tmpfs:** `/tmp` (16 MiB, `mode=1700`) and `/work` (`size=96m,mode=0711,noexec`). `/work` is the render work dir, laid out by `cyberlab_worker.sandbox.prepare` (RT4).
  - **`api-test`** gains `REPORTS_BUCKET: ${REPORTS_TEST_BUCKET}` and `TEST_BROKER_REPORT_URL` (for the ACL tests).
  - **Image** `cyberlab/report-worker:dev` from `apps/workers/report/Dockerfile`:
    - python:3.12-slim with the pinned dependencies (`weasyprint>=70.0,<71`, `fonttools>=4.60.2`, `jinja2>=3.1.6`, `celery[redis]`, `cyberlab-jobs`, `cyberlab-worker`), locked in `apps/workers/report/uv.lock`;
    - Debian `libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0 libseccomp2 fonts-noto-core fonts-noto-mono`;
    - **no Ghostscript**; a test asserts that `gs` is absent (RT16);
    - a fontconfig that lists only `/usr/share/fonts/truetype/noto`, with the cache built at image build time (`fc-cache`);
    - the worker runs as root inside the container, as the analyzers do, and drops the render subprocess to the `tool` user, uid 10003 (RT3).
  - `mem_limit: 1g`, `pids_limit: 128`, `cpus: 1`, `networks: [analysis]`, env only `BROKER_URL` (broker user `report`).
  - The prod overlay uses the prod image with `ENV=prod`, and requires `BROKER_REPORT_PASSWORD`.
  - The dev default is `${BROKER_REPORT_PASSWORD:-change-me-broker-report}`, so older `.env` files still start (the M5 RT25 lesson).
- **Broker ACL** (`infra/redis-broker/entrypoint.sh`):
  - user `report`: `resetkeys ~report* ~test.report*` plus its kombu bindings; publish to `ingest` the same way the analyzers do;
  - `api` and `ingest` can publish to `report*`;
  - `pcap`, `static`, `enrich` and `analyst` cannot touch `report*`, and `report` cannot touch `enrich*`, `analyst*` or `trusted.*`.
- **Worker skeleton** `apps/workers/report/`:
  - `report_worker/app.py`: Celery on queue `report`, **prefork `--concurrency 1 --max-tasks-per-child 1`** with the analyzers' flags (the solo pool enforces neither the child recycling nor the hard limit, RT4), `task_time_limit=120`, `task_soft_time_limit=90`, remote control and events off;
  - `report_worker/tasks.py`: `report.render` replies `ReportRenderedV1{status: failed, error_code: not_implemented}`;
  - `tests/test_skeleton.py`;
  - `tests/test_isolation.py` (RT21): the worker-kit isolation checks for the report hosts. The env holds only `BROKER_URL`; there is no route to `postgres`, `redis`, `api`, `web` or `gateway`, and no egress.
  - Phase 4 owns everything after that.
- **Worker kit** (`packages/py-worker-kit`, shared, RT3). The defaults keep the analyzers' behaviour, and their tests stay green.
  - `run_tool(..., rlimits: Rlimits | None = None)`, with `Rlimits{as_bytes, cpu_s, fsize_bytes, nofile, nproc}`.
  - `seccomp.deny_network(extra_domains: Sequence[int] = (), deny_io_uring: bool = False)`. The report worker passes `(AF_NETLINK,)` and `True`, and `io_uring_setup` gets `EACCES`.
  - Tests in `packages/py-worker-kit/tests/test_sandbox.py`.
- **Snapshot reads** (RT14): `core/tenancy.tenant_session(..., snapshot_read: bool = False)` begins the transaction as `REPEATABLE READ READ ONLY` (connection execution options) before `set_config`, with a unit test that a write inside it fails.
- **Lane wrapper** (RT21): `scripts/lane-test.sh <lane> --service report-worker-test <cmd…>` runs the named test service with the same slot lock and broker db.
- **Stub routes:** every path in the phase-2/3/4/5 route tables, with method, permission dependency, request model, response model and status code exactly as specified there. Each body raises `HTTPException(501, "not_implemented")`.
  - This includes `GET /reports/{rid}/versions/{v}/content` (`evidence.read`; response model `ReportSnapshot`, RT11).
  - `GET /api/v1/report-signing-keys` is implemented here because it is small: **unauthenticated**, rate-limited per IP, no org; it returns the public keys only (RT22).
- **Cross-phase stubs** (RT10, RT11):
  - `ioc_collections/case_iocs.py: case_iocs(...)` (owned by phase 2, called by the phase-3 snapshot builder);
  - in `investigations/timeline.py`: `page(..., kinds=None)` (accepted and ignored until phase 5), `Entry.evidence_id: uuid.UUID | None`, `RefKindName.NOTE` / `STATUS`;
  - in `investigations/router.py`: the existing timeline route gains the `kinds` query parameter and passes it on;
  - in `investigations/schemas.py`: `TimelineEntryOut.evidence_id` becomes optional.

  The existing timeline and AI tests must stay green; the web timeline view treats a null `evidence_id` as "case event".
- **Audit actions:** `apps/web/lib/audit-actions.ts` gains every M6 action name (`note.*`, `ioc_collection.*`, `case_attack.*`, `report.*`, `evidence.share_policy_updated`, `investigation.timeline_exported`) (RT11).
- **Ingest and reaper:** `workers/tasks.py` registers `report.rendered` → `reports.render_ingest.handle_rendered` (stub). `reap` calls `reaper.reap_report_renders()` (stub returning 0).
- **Test infrastructure:**
  - `tests/case_helpers.py`, `tests/report_helpers.py`, and the fixtures `tests/fixtures/report/{hostile_snapshot,golden_snapshot}.json` (also copied to `apps/workers/report/tests/fixtures/`);
  - the IDOR module split (`idor_cases_{case,reports,renders,attack}.py`, empty except for their `PENDING_ROUTES`, merged by `test_idor_routes.py`);
  - `test_rls_coverage.py` and `test_append_only.py` register the new tables;
  - `test_tenant_session_guard.py` allowlists the new trusted file (`reports/render_ingest.py`);
  - the `apps/web/components/reports/case-reports-panel.tsx` stub with props `{orgId: string; investigationId: string}`, which renders a link to `/o/{org}/reports?investigation={inv}`.
- **Shared web pieces** (implemented and frozen, used by phases 6 and 7):
  - `apps/web/lib/tlp.ts` (order, labels, FIRST colours, `isDowngrade`; a test keeps it in sync with the OpenAPI enum);
  - `components/tlp/{tlp-badge,tlp-select}.tsx`: label text always present, an `aria-label`, and a downgrade confirm with the acknowledgement checkbox, disabled for users without `org.update`;
  - `apps/web/lib/vis-rules.json`, a copy of `packages/py-jobs/src/cyberlab_jobs/vis_rules.json` (the code points and ranges made visible: C0/C1 controls except `\n\t`, bidi overrides and isolates, zero-width, tag characters and every other `Cf` character).
    - The JSON is a **materialized range list**, generated by `scripts/gen_vis_rules.py` from the M5 `ai/text.py` categories under Python 3.12 `unicodedata`. No runtime "category Cf" check happens on either side, so browser ICU versions cannot drift (RT24).
    - A test regenerates and compares, and another asserts that the two copies are equal. The renderer and the viewer both load the table.
- **Contracts:** after the stubs land, run `pnpm gen:contracts` once and commit `packages/contracts/{openapi.json,src/schema.d.ts}`.

## Implementation Steps
1. Pre-flight checks and dependency verification; branch.
2. Migration 0012, the models and `integration/test_m6_schema.py`:
   - RLS per table, cross-org FKs, append-only (owner included);
   - each guard trigger, column grants, no DELETE, checks;
   - backfilled defaults; upgrade and downgrade.
3. The `py-jobs` report contract and its unit tests (`packages/py-jobs/tests/test_report_contract.py`).
4. Policy, call sites and tests (unit plus AI preview/run, incident skip, analyst-worker and enrich-worker re-checks with mock call counters).
5. Signing core, keys, settings, prod guards, import guard; `unit/test_config.py` additions (only the api role may hold `REPORT_SIGNING_KEYS_FILE`; prod refuses `dev-report-*` kids and the dev public key); `unit/test_signing.py`.
6. Stub routers and schemas for every route, the signing-keys route, `app/main.py` registration, and `pnpm gen:contracts`.
7. Compose, broker ACL, MinIO bucket and policy, and the report-worker image and skeleton:
   - `integration/test_report_acl.py`;
   - `apps/workers/report/tests/test_isolation.py`, run in `report-worker-test` through `scripts/lane-test.sh 4 --service report-worker-test` (RT21): no default route, cannot resolve `api`, `postgres`, `redis`, `web` or `gateway`, can reach only the broker and MinIO, and an env with only `BROKER_URL`;
   - the worker-kit tests (`packages/py-worker-kit/tests`) for the `Rlimits` and the netlink / io_uring deny, plus the existing pcap and static isolation suites unchanged (RT3).
8. Re-run the full API suite, `pnpm verify`, and `docker compose -f docker-compose.yml -f docker-compose.prod.yml config` (the report-worker with `ENV=prod`, no signing material and no MinIO credentials). Write "Frozen interfaces (as built)" with the exact signatures.
9. **Lane setup (parent):**
   - rebuild `cyberlab/api:dev` and `cyberlab/report-worker:dev`;
   - create worktrees `m6/b2` … `m6/b7` with `.env` copies;
   - run `tests/unit/test_signing.py` once in lanes 2–5, and `test_skeleton.py` in `report-worker-test`, as smoke tests.

## Success Criteria
- [ ] Migration 0012 is applied and tested: RLS, FORCE, policies, composite FKs, append-only for the owner too, every guard trigger, column grants, no DELETE, upgrade and downgrade.
- [ ] The snapshot contract produces byte-identical canonical JSON across key orders and Python runs. The caps reject oversize input, and the worst case stays ≤ 8 MiB.
- [ ] With the policy on, AI preview, run creation and TI enrichment answer `409 policy_blocked`. The worker re-checks fail an in-flight run with 0 provider calls. Existing cases behave as in M5.
- [ ] Only the api role holds the signing key. Prod refuses dev kids and keys. The import guard passes.
- [ ] The report-worker runs on `analysis` only, with only `BROKER_URL`, as root dropping to uid 10003, on the prefork pool. The broker ACL confines `report`. The worker kit's new `Rlimits` and the netlink / io_uring deny are tested, and the analyzers' suites are unchanged.
- [ ] `reports` and `reports-test` exist with object lock and no default retention. `api-test` uses `reports-test`, and the MinIO policy has no delete on either.
- [ ] The M5 prompt-pin test is unchanged (`policy_excluded` is not rendered). The timeline answers with nullable `evidence_id` and accepts `kinds`, and the M5 timeline and AI tests stay green.
- [ ] Every new route exists as a 501 stub with frozen schemas. The contracts are generated and committed, and the IDOR enumerator lists every route. Unfilled routes are reported as pending (`PENDING_ROUTES`), never silently passed.
- [ ] `pnpm verify` is green.

## Risk Assessment
- **Editing M4 / M5 files** right after their gates: `ai/service_runs`, `ai/context/builder`, `ai/contracts`, `workers/analyst` (70 KB), `threat_intel/service_runs`, `workers/enrich` (47 KB), the timeline and the worker kit. The changes are additive call sites and defaulted parameters only. The full M4 and M5 suites and the pcap and static isolation suites must stay green before the phase is committed (RT3, RT10, RT20).
- **Freezing ~40 route schemas up front.** This is the price of frontend parallelism. Change requests go to the parent, and the merge step diffs the contracts.
- **WeasyPrint wheel or system-library mismatch** on slim images. If a build fails, pin the Debian WeasyPrint-compatible Pango; the Dockerfile records the versions.
- **IDOR enumerator strictness:** with empty case modules, `test_idor_routes.py` would fail for every new route. To prevent that, each case module also exports `PENDING_ROUTES: frozenset[(method, path)]`, which phase 1 fills with that module's routes. The enumerator skips pending routes with a visible count. Each owning phase empties its own set while it adds the cases, so no shared file is touched. Phase 9 asserts that every `PENDING_ROUTES` set is empty.

## Frozen interfaces (as built)

Written at the end of phase A (code) and verified in phase B (containers: dev stack up with the report-worker, full api suite, worker-kit / pcap / static / report-worker suites, web checks, e2e, prod compose config). Deviations from plan.md are marked **(deviation)**; phase-B changes are marked **(phase B)**.

**Phase B verification notes:**
- Dependencies (`apps/workers/report/uv.lock`, resolved 2026-11-05): `weasyprint 70.0`, `fonttools 4.68.0`, `jinja2 3.1.6`, `pydyf 0.13.0`, `pillow 13.0.0`, `tinycss2 1.5.1`, `cssselect2 0.10.1`, `tinyhtml5 2.1.0`, `celery 5.6.3`, `pydantic 2.14.3`. All satisfy the pins (`weasyprint>=70.0,<71` covers CVE-2025-68616 / CVE-2026-49452 / CVE-2026-55073 / CVE-2026-106443; `fonttools>=4.60.2` covers CVE-2025-66034; `jinja2>=3.1.6`). OSV query for these exact versions: no advisories. PyPI latest WeasyPrint is 70.0.
- `vis_rules.json` and `apps/web/lib/vis-rules.json` generated (Unicode 15.0.0, byte-identical).
- Results (2026-11-05): api ruff / format / mypy clean, pytest 3718 passed, 44 skipped; worker kit 40 (in the pcap and static images), pcap 48, static 252, report-worker 29 (skeleton + isolation); web typecheck + eslint + 322 vitest; dev e2e 8 passed, 2 prod-only skipped; prod compose config: report-worker has only `BROKER_URL` + `ENV`, `analysis` only, signing material only on `api` (prod kid).
- Local secrets: `BROKER_REPORT_PASSWORD`, `REPORT_PROD_SIGNING_ACTIVE_KID` / `REPORT_PROD_SIGNING_PUBLIC_KEYS` in `.env` (git-ignored) and `.secrets/report_signing_private.json` (0400, written by the script as root in the api image, owner 10001).

**Migration `0012_reports_case_mgmt.py`** (down_revision `0011`):
- `investigations` + `tlp text NOT NULL DEFAULT 'amber'` (`ck_investigations_tlp`), `ai_excluded`, `ti_excluded` (bool, default false).
- Tables as in the plan's data model. Text + CHECK, no Postgres enums. Composite `(id, organization_id)` FKs everywhere; `ioc_collection_items.ioc_id -> iocs.id` and `report_citations.ai_citation_id -> ai_citations.id` are plain FKs (those parents have no `(id, org)` unique). **(integration, review L4: migration `0013_m6_same_org_fks` adds `uq_iocs_id_organization_id` / `uq_ai_citations_id_organization_id` and makes both composite same-org FKs.)**
- **(deviation)** `ioc_collection_items` uniqueness is a partial unique index `(collection_id, ioc_key) WHERE removed_at IS NULL` (a removed item can be re-added as a new row, phase 2). `ioc_collections`: unique index `(investigation_id, lower(name))`. `report_renders`: partial unique `(version_id, format, coalesce(renderer_version, '')) WHERE status <> 'failed'`.
- Triggers `analyst_note_guard`, `ioc_collection_item_guard`, `report_guard` (revision must be exactly +1 on **every** UPDATE, including the finalize write), `report_render_transition` (queued -> running | failed; running -> succeeded | failed; there is no queued -> succeeded edge: ingest passes through `running`). `forbid_mutation` on the four append-only tables.
- Extra checks: `report_renders` `succeeded` needs sha256 + bytes + object_version_id; `failed` needs error_code; `report_versions.schema_version = 'cyberlab.report.v1'`; signature `^[A-Za-z0-9+/]{86}==$`.
- `ti_run_items.reason` CHECK gains `policy_blocked` (`ITEM_REASONS`, `schemas.ItemReason`). `ai_runs.error_code` has no CHECK.
- Grants: S/I on every new table, UPDATE per column as in the plan; `report_render_index` UPDATE (`status, dispatched_at, deadline_at, attempts`); policy `render_index_scope` (system sessions see all rows).

**Models:** `investigations/models.py` (`Investigation.tlp/ai_excluded/ti_excluded`, `InvestigationStatusEvent`, `EvidenceSharePolicy`, `TLP_VALUES`), `notes/models.py` (`AnalystNote`, `AnalystNoteVersion`), `ioc_collections/models.py` (`IocCollection`, `IocCollectionItem`), `case_attack/models.py` (`CaseAttackMapping`), `reports/models.py` (`Report`, `ReportVersion`, `ReportCitation`, `ReportRender`, `ReportRenderIndex`). All registered in `app/models.py`.

**Contract `cyberlab_jobs/report.py`:**
- `REPORT_SCHEMA = "cyberlab.report.v1"`, `MANIFEST_SCHEMA = "cyberlab.report.manifest.v1"`, `RENDER_SCHEMA = "report.render.v1"`, `RENDERED_SCHEMA = "report.rendered.v1"`.
- **(deviation)** the schema field is `schema_version` (snapshot, manifest, messages), not `schema` (a pydantic field named `schema` shadows `BaseModel.schema`). The manifest also carries `report_schema`.
- Constants: `MAX_SNAPSHOT_BYTES` 8 MiB, `MAX_ARTIFACT_BYTES` 32 MiB, `MAX_PAGES` 300, `CAPS` (status_history 200, document_control 100, evidence 500, custody 2000, jobs 200, findings 500, alerts 500, iocs 2000, ti 2000, attack 500, timeline 1000, notes 200, ai_runs 10, ai_claims 200, citations 2000), `ROW_UNITS` 40, `CITATION_UNITS` 60.
- TLP: `TLP` StrEnum, `TLP_ORDER`, `TLP_LABELS`, `TLP_COLOURS` (text colour; `TLP_BACKGROUND = "#000000"`), `TLP_DEFINITIONS`, `STIX_TLP_EXTENSION_ID`, `STIX_TLP_MARKINGS: dict[TLP, dict]` (checked against the OASIS `tlp-2.0/examples` AMBER+STRICT object). `ReportProfile` (`internal/external`) with the alias `Profile = ReportProfile` **(phase B: the class was `Profile`, which collided in OpenAPI with the M2 static-analysis `Profile` and broke `test_openapi_names` and the web `Schemas["Profile"]`; the OpenAPI component is `ReportProfile`)**.
- Text: `BoundedText` (<= 4096, cut with `…[truncated n]`, idempotent), `AnalystText` (<= 20000, refused above), `Title` (1..200), `ShortNote` (<= 500); all refuse NUL and lone surrogates. `FixedPoint` decimal strings, `Timestamp` (aware, serialized `YYYY-MM-DDTHH:MM:SS.ffffffZ`), `BaseUrl` (https origin or http localhost), `TechniqueId`, `RefId`, `Ident`, `CiteNo`.
- Models: `ReportSnapshot{schema_version, report: ReportInfo, case: CaseSection, sections: AnalystSections, evidence, custody, jobs, findings, alerts, iocs, ti, attack, timeline, notes, ai, citations}`. Each list section is `XxxSection{items, total}` (`EvidenceSection`, `CustodySection`, `JobsSection`, `FindingsSection`, `AlertsSection`, `IocsSection`, `TiSection`, `AttackSection`, `TimelineSection`, `NotesSection`, `AiRunsSection`, `CitationsSection` + `dropped_out_of_scope`). Item models: `EvidenceItem`, `CustodyItem`, `JobItem`, `FindingItem`, `AlertItem`, `IocItem`, `TiItem`, `AttackItem`, `TimelineItem`, `NoteItem`, `AiSection`, `AiClaim`, `Citation`, `StatusEventItem`, `DocumentControlItem`, `ReportInfo` (report id, version, title, template, tlp, profile, distribution, generated_by, finalized_at, base_url, change_note, document_control). Every cited `[Cn]` must exist in `citations` (validator).
- Functions: `canonical_json(model | dict | list) -> bytes`, `parse_snapshot(bytes)`, `render_units(snapshot) -> int` (golden fixture pinned at **4768**), `section_units`, `section_counts`, `truncate_text`, `rfc3339`, `manifest_bytes(Manifest)`.
- `Manifest{schema_version, report_schema, report_id, version, org_id, snapshot_sha256, snapshot_bytes, tlp, profile, finalized_at, finalized_by, kid}`; `ReportSignatureFile{alg, kid, manifest, signature}`.
- `ReportRenderMessageV1{schema_version, render_id, org_id, format, snapshot_url, snapshot_sha256, snapshot_bytes, manifest_b64, signature, kid, finalized_at, upload: PresignedPost, token, deadline}`; `ReportRenderedV1{schema_version, render_id, token, status, sha256, bytes, pages, object_version_id, renderer_version, error_code}` **(deviation: + `object_version_id`, required when succeeded)**. `RENDER_FORMATS`, `RenderFormat`, `RENDER_CONTENT_TYPES`, `RENDER_ERROR_CODES`, `RenderErrorCode`.
- `tasks.py`: `REPORT_RENDER`, `REPORT_RENDERED`, `Queues.report`. `cyberlab_jobs/vis.py`: `vis(text)`, `is_invisible(cp)`, `rules()`; `vis_rules.json` is generated by `scripts/gen_vis_rules.py` (phase B, in the api image) and copied to `apps/web/lib/vis-rules.json`.
- Tests: `apps/api/tests/unit/test_report_contract.py` **(deviation: not `packages/py-jobs/tests`, which no service runs)**. Fixtures: `apps/api/tests/fixtures/report/{golden,hostile}_snapshot.json`, copied to `apps/workers/report/tests/fixtures/`.

**Policy `investigations/policy.py`:** `SharePolicy{ai_blocked, ti_blocked, reasons, excluded_evidence_ids, ti_excluded_evidence_ids, ai_reasons, ti_reasons}` (+ properties `ai_reason`, `ti_reason`) **(deviation: + `ti_excluded_evidence_ids`, `ai_reasons`, `ti_reasons`)**; `async load_policy(session, org_id, *, investigation_id=None, job_ids=(), evidence_ids=())`; `PolicyBlocked(code="policy_blocked", reason=...)` = `409` with `error.reason`; `tlp_at_least(a, b)`, `is_downgrade`, `case_policy(tlp, ai_excluded, ti_excluded)`, `raise_if_ai_blocked`, `raise_if_ti_blocked`; reasons `tlp_red`, `case_ai_excluded`, `case_ti_excluded`, `evidence_ai_excluded`, `evidence_ti_excluded`. `AppError` gained `extra=` (rendered next to code/message).
- Call sites: `ai/service_runs._prepare -> _check_policy` (preview + run); `ai/context/builder._case_jobs` (returns a `_Case` dataclass; skips AI-excluded evidence in jobs, scope, `K` items and timeline; `_with_policy_count` sets `ContextStats.policy_excluded`, never rendered); `ai/context/select.evidence_items(..., exclude=)` and `case_timeline_items(..., exclude_evidence=)` (additive); `workers/analyst._Work._policy_blocked` before `_estimate` (count_tokens) and again before the call for Anthropic -> `AiErrorCode.POLICY_BLOCKED`; `threat_intel/service_runs._create` (job scope); `workers/enrich._policy_blocked` before each slice -> finalize with abandon reason `policy_blocked`.

**Signing:** `app/core/signing.py`: `load_signing_keys(path)`, `load_public_keys(mapping | json)`, `public_key_b64(key)`, `sign(manifest_bytes, kid, keys) -> str`, `verify(manifest_bytes, signature_b64, kid, public_keys) -> bool`, `SigningError(code)`. `app/modules/reports/signing.py` (only importer of the loader): `sign_manifest(bytes) -> (signature, kid)`, `verify_manifest`, `public_keys()`, `active_kid()`, `reset_cache()`. Settings `report_signing_keys_file` (api role only), `report_signing_public_keys`, `report_signing_active_kid`; prod api requires the kid and the key file, refuses `dev-` kids and `DEV_REPORT_SIGNING_PUBLIC_KEYS`. Dev pair `infra/reports/dev-signing-private.json` (kid `dev-report-1`). `scripts/gen_report_signing_keys.py` prints `REPORT_PROD_SIGNING_ACTIVE_KID` / `REPORT_PROD_SIGNING_PUBLIC_KEYS` (required by the prod overlay).

**Other shared code:** `app/core/csv_safe.py` (`csv_safe`, `write_csv(rows, header_comment=None) -> Iterator[bytes]`); `app/core/stubs.py` (`not_implemented()` = `501 not_implemented`); `tenant_session(..., snapshot_read=False)`; settings `reports_bucket`, `report_max_*`, `report_render_deadline_s`, `report_render_timeout_s`, `report_*_per_user_10min`, `report_active_renders_*`, `timeline_export_max_rows`, `public_base_url` (origin only; https in prod outside localhost); `REPORT_DEFAULT_MAX_RENDER_UNITS = 450_000` (**integration:** the phase-4 calibration; phase 1 shipped the 750_000 estimate). Worker kit: `sandbox.Rlimits{as_bytes, cpu_s, fsize_bytes, nofile, nproc}`, `run_tool(..., rlimits=None, deny_extra_domains=(), deny_io_uring=False)` **(deviation: the seccomp options are `run_tool` kwargs)**, `seccomp.deny_network(extra_domains=(), deny_io_uring=False)` (io_uring_setup/enter/register -> EACCES), `transfer.upload(post, path, *, filename=..., content_type=...)` **(deviation: added for the renderer)**.

**Timeline (RT10):** `RefKindName.NOTE/STATUS`, `TimelineKind = RefKindName`, `Entry.evidence_id: UUID | None`, `page(..., kinds=None)` (ignored), route `?kinds=` (repeatable), `TimelineEntryOut.evidence_id: UUID | None`.

**Schemas and stub routes** (all `501` after the permission dependency): `investigations/schemas.py` (`InvestigationUpdate` + `tlp, ai_excluded, ti_excluded, status_reason, acknowledge_tlp_downgrade: bool | None = None` **(phase B: was `bool = False`; openapi-typescript makes defaulted fields required, so every existing PATCH body would have needed it; explicit null is refused like the other fields; only `true` acknowledges)**; `InvestigationOut` + `tlp, ai_excluded, ti_excluded, share_policy: SharePolicyOut`; `StatusEventOut/Page`; `EvidenceSharePolicyIn/Out`). Until phase 2, a PATCH setting any M6 field answers 501 (`service.M6_UPDATE_FIELDS`). `EvidenceOut` + `ai_excluded`, `ti_excluded` (default false). `notes/schemas.py`, `ioc_collections/schemas.py`, `case_attack/schemas.py`, `case_timeline/schemas.py`, `reports/schemas.py` (`ReportDraft` with the 1 MiB check, `ReportCreate/Update/Finalize`, `ReportOut/Detail/Page`, `ReportPreviewOut`, `ReportVersionSummary/Detail/List`, `ReportSignatureOut`, `CitedByOut`, `RenderCreate/Out/List`, `SigningKeysOut`). Routers: `notes/router.py`, `ioc_collections/router.py`, `case_attack/router.py`, `case_timeline/router.py`, `reports/router.py`, `reports/router_renders.py`, the status-events route in `investigations/router.py`, share-policy routes in `evidence/router.py`; implemented `reports/router_keys.py` (`GET /api/v1/report-signing-keys`, 60/min per IP). Path parameters: `{note_id}`, `{collection_id}`, `{item_id}`, `{mapping_id}`, `{report_id}`, `{version}` (int), `{render_id}`. Finalize answers `ReportVersionSummary` (201).

**Cross-phase stubs:** `reports/snapshot.py` (`CitationRow`, `BuiltSnapshot`, `build_snapshot`), `reports/cited_by.py`, `reports/dispatch.py` (`create_render`, `dispatch_render`), `reports/render_ingest.py` (`handle_rendered(msg)`, plus `handle_rendered_message(dict)` used by the `report.rendered` task in `workers/tasks.py`), `workers/reaper.reap_report_renders()` (returns 0, called by `reap`), `case_attack/suggest.py`, `ioc_collections/case_iocs.py` (`MAX_PAGE = 500`).

**Tests and helpers:** `tests/case_helpers.py` (`seed_case`, `set_case_policy`, `seed_evidence`, `seed_job_on`, `set_evidence_policy`, `seed_status_event`, `seed_note`, `seed_collection`, `seed_collection_item`, `seed_mapping`), `tests/report_helpers.py` (`new_signing_keys`, `use_signing_keys`, `fake_snapshot`, `hostile_snapshot`, `golden_data`, `seed_report`, `seed_version -> SeededVersion`, `seed_render -> (id, token)`, `purge_reports_test_bucket`, `reports_test_bucket`). IDOR: `idor_cases_{case,reports,renders,attack}.py` with `PENDING_ROUTES` (17 + 14 + 4 + 5 = 40 routes), merged by `test_idor_routes.py`. `test_tenant_session_guard.PENDING_ALLOWED` = `{modules/reports/render_ingest.py}` (phase 4 empties it). New: `unit/test_{report_contract,csv_safe,signing,report_import_guard,share_policy,vis_rules}.py`, `integration/test_{m6_schema,m6_foundation,share_policy,report_acl}.py`; updated `test_config.py`, `test_rls_coverage.py`, `test_migrations.py`, compose env fixtures.

**Infra:** compose `x-report-worker`, `report-worker`, `report-worker-test` (profile test, not an api-test dependency), `x-report-signing-env` (api only) + secret `report_signing_private`; api-test `REPORTS_BUCKET=reports-test`, dev public keys, no key file, `TEST_BROKER_REPORT_URL`; broker user `report` (`analyzer_keys report`); MinIO `reports` / `reports-test` (lock, no default retention, `reports-test-lifecycle.json`, policy without delete); `scripts/lane-test.sh <lane> --service report-worker-test ...`; report worker skeleton `apps/workers/report` (Dockerfile without Ghostscript, `assets/fonts.conf`, `report_worker/{config,app,tasks}.py`, `tests/{test_skeleton,test_isolation}.py`); `uv.lock` (phase B). `report-worker-test` sets `MYPY_CACHE_DIR=/dev/null` **(phase B: the 16 MiB `/tmp` cannot hold the mypy cache)**. Web: `lib/tlp.ts` (+ test, also checks the vis-rules copy), `components/tlp/{tlp-badge,tlp-select}.tsx`, `components/reports/case-reports-panel.tsx`, `lib/audit-actions.ts`; `lib/ti.ts` `ITEM_REASON_TEXT.policy_blocked` **(phase B, required by the `Record<ItemReason, string>` type)**. Contracts `packages/contracts/{openapi.json,src/schema.d.ts}` generated in phase B.

**Phase B test fixes (tests only):** `test_m6_schema` cross-org FK test (the foreign evidence already had a share-policy row and the foreign version a live `pdf` render, so the PK / unique index fired before the FK); `test_share_policy` AI refusal test uses `incident_builder([job])` (the default fake builder invents job ids, which the `job_digest` children's FK rejects); `test_ti_key_leak.GLOBAL_GETS` + `/api/v1/report-signing-keys`; `test_config.test_report_defaults` clears the api-test `REPORTS_BUCKET`; `lib/ai.test.ts` fixture + `policy_excluded`.

**Not done in phase 1:** a `check-report-env.mjs` gate script (the prod env fixture is updated by hand), the web `AI_ERROR_TEXT` entry for `policy_blocked` (phase 6).
