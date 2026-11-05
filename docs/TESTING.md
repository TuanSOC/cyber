# Testing

## Commands

| Command | What |
|---|---|
| `pnpm verify` | everything below + Playwright, from the dev stack |
| `pnpm verify:prod` | `verify` + prod stack health, headers, HSTS |
| `pnpm test:api` | API test suite (real Postgres, Redis, MinIO; no mocks of analysis or storage) |
| `pnpm lint:api` | ruff, format check, mypy `--strict` |
| `pnpm lint:web` | Next typegen + tsc, eslint, vitest |
| `pnpm test:workers` | Both workers, each inside its real image (tools, seccomp, caps): ruff, format, mypy, engine, evaluation and fuzz-lite tests of the pcap worker, then of the static worker; the shared worker kit suite (sandbox, isolation, broker ACL) runs in both images |
| `pnpm e2e` | Playwright golden path against the running stack (`pnpm e2e --prod` for the prod-like stack) |
| `pnpm gen:contracts` | Regenerate the OpenAPI contract and TS types (`verify` fails on drift) |

To prove the gate from empty volumes without touching dev data, stop the dev stack (`pnpm down`, volumes kept) and run `COMPOSE_PROJECT_NAME=cyberlab-clean pnpm verify`, then `COMPOSE_PROJECT_NAME=cyberlab-clean docker compose down -v`.

Test isolation: the API suite uses `cyberlab_test`, Redis db 1 and the `evidence-test` bucket; the harness refuses any database not ending in `_test` and Redis db 0, truncates tables and flushes Redis around each test, and purges the test bucket (including locked versions) at session start/end.

## Current results

- API: ~810 tests (unit, integration, security, incl. analysis jobs, ingest validation, read API and a real-worker pipeline). Typical run ≈ 3 min.
- PCAP worker: ~55 tests inside the worker image: sandbox and container isolation (uid, caps, seccomp, egress, broker ACL, escaped / non-dumpable processes, planted symlinks), real engines over the synthetic dataset, hostile tool output, detection evaluation, fuzz-lite.
- Static worker (M3), inside its image (`apps/workers/static/tests`):
  - `unit/`: detections (incl. a test that rejects verdict words in templates), IOC extraction, hostile probe / capa / FLOSS / ClamAV output, sample builders, pipeline;
  - `integration/test_engines.py`: real engines over the synthetic set (EICAR, test marker, archives never silently clean, missing AV DB, size caps, fresh out dir per engine, probes as uid 10003, no surviving tool process);
  - `evaluation/`: detection quality and fuzz-lite (below).
- Worker kit (`packages/py-worker-kit/tests`): sandbox, isolation and result-writer tests, run in both worker images.
- API (M3 additions): `test_analysis_static.py` (auto-run rules, profiles, per-analyzer caps, `sample_too_large`), `test_static_results.py` (hostile `static.v1` streams → `invalid_result` with zero rows, read API, foreign / pcap jobs → 404, report headers, caps and audit); the new routes are also covered by the auto-enumerated `test_idor_routes.py`, `unit/test_static_stream.py`, `test_storage_quota.py` (declared and undeclared length, concurrent uploads, archived evidence, column grants, owned-org limit).
- Static pipeline end to end: `apps/api/tests/integration/test_analysis_static_pipeline.py` uploads a plain file (`av`) and a PE (`full`) through the real broker and the real `static-worker-test` container, ingests the result, checks the sample hashes against the evidence and downloads the report. It runs in `pnpm test:api`.
- API (M4 additions): the threat-intel suites, the enrich worker pipeline through `ti-mock` and the network tests; see [M4 threat intelligence suites](#m4-threat-intelligence-suites).
- API (M5 additions): the AI analyst suites, the evaluation harness and the analyst network tests; see [M5 AI analyst suites](#m5-ai-analyst-suites).
- API and report-worker (M6 additions): case management, share policy, reports, signing, renders and the renderer's sandbox; see [M6 reports and case management suites](#m6-reports-and-case-management-suites).
- Web: unit tests (redirect safety, CSP builder, pcap and static result helpers, TI wording and helpers), typecheck, lint, production build.
- E2E: Playwright specs, run against dev (`pnpm e2e`) and the prod-like stack over TLS (`pnpm e2e --prod`, part of `verify:prod`), with no console errors:
  - `smoke.spec.ts`: register → create case → upload (hash checked against a locally computed SHA-256) → verify → custody chain → sign out;
  - `pcap.spec.ts`: capture upload → automatic PCAP analysis → findings;
  - `malware.spec.ts`: synthetic PE upload → automatic static analysis (`full`) → Malware Lab results and report;
  - `csp.spec.ts`: fresh nonce per HTML response, strict policy on the API, pages hydrate, injected markup without the nonce is blocked;
  - `threat-intel.spec.ts`: the M4 enrichment flow on the `mock` provider (prod: `mock` refused);
  - `ai-analyst.spec.ts` (M5): dev: AI on with the privacy acknowledgement, the `mock` key stored and verified, a capture summarized (preview with pseudonyms, one rate-limit pause, then completed), a verified citation chip opening the cited finding, "Explain" on a finding, a hostile capture (no extra link, hidden-statement counter, verdict note), an incident summary and the AI runs list, no key in any page; prod: `mock` absent from the catalog and `PUT` refused with 422 `provider_unavailable`.
- Observed once during development: a `pnpm verify` run had 13 API test failures (CSRF/auth-event assertions) right after the stack was recreated; not reproduced in later runs (including from fresh volumes). Tracked as a possible flake — rerun before investigating.

### E2E side effects

E2E runs against the real stack, not the test database. Each run:
- clears the per-IP register rate-limit keys (`rl:register:*`) in that stack's Redis, so repeated runs do not hit 429; every spec registers one user, so the specs run in batches of five (the limit per 10 minutes) with the keys cleared before each batch;
- leaves one user, one organization, one case and one small evidence object behind. The object is governance-locked for `EVIDENCE_LOCK_DAYS` (30 by default) and cannot be deleted by the app. Use `docker compose down -v` to reset a dev stack.

## Requirement coverage (§13 / §14 of `requirement.txt`)

| Requirement | Status | Where |
|---|---|---|
| IDOR | ✅ every org-scoped route, auto-enumerated from OpenAPI | `tests/security/test_idor_routes.py` |
| Cross-tenant access | ✅ | `test_idor_routes.py`, `test_rls.py`, `test_rls_coverage.py`, `test_investigations.py`, `test_evidence.py` |
| Unauthorized evidence download | ✅ 401 (no session), 404 (non-member), viewer allowed + logged | `test_idor_routes.py`, `test_evidence.py` |
| Malicious file upload | ✅ path traversal, CRLF, bidi, NUL, huge names, 0-byte, EICAR | `test_malicious_filenames.py`, `test_evidence.py` |
| Archive bombs | ✅ stored opaque, never extracted | `test_malicious_filenames.py` |
| Session security | ✅ rotation, reuse, grace window, concurrency, CSRF, JWT forgery, rate limits, Redis outage | `test_auth.py`, `test_auth_rate_limit.py`, `test_security.py` |
| Evidence integrity | ✅ hashes, version pinning vs overwrite, retention lock, mismatch/missing detection | `test_evidence.py`, `test_storage_minio.py`, `test_hashing.py` |
| Audit immutability | ✅ | `test_append_only.py` |
| RBAC: viewer cannot upload/verify, analyst cannot manage members | ✅ every role × permission over HTTP | `test_rbac.py::test_role_permission_matrix`, `test_orgs_members.py`, `test_evidence.py` |
| RLS with no tenant context returns zero rows | ✅ | `test_rls.py::test_no_context_sees_no_tenant_rows` |
| Refresh reuse revokes the whole family (and its access tokens) | ✅ | `test_auth.py::test_reuse_after_grace_revokes_whole_family`, `::test_reuse_detection_also_kills_access_tokens_of_the_family` |
| Oversized upload leaves no object, row or temp file | ✅ | `test_evidence.py::test_oversize_stream_is_rejected_without_leftovers`, `::test_declared_oversize_is_rejected_before_reading` |
| Evidence retention lock | ✅ | `test_evidence.py::test_uploaded_version_is_retention_locked`, `test_storage_minio.py` |
| Positive control for every IDOR case (owner request succeeds) | ✅ | `test_idor_routes.py::test_owner_request_succeeds` |
| Malware scanning of uploads | ✅ M3: ClamAV + YARA on every non-empty upload ≤ 64 MiB; never "clean" when not fully scanned | `test_analysis_static.py::test_auto_run_matrix`, static worker `test_engines.py` |
| Data retention / expiry policy | ⏳ later (only the 30-day governance lock exists) | — |
| Backup / restore | ⏳ later | — |
| Parser vulnerabilities | ⏳ M2+ (no parsers yet; evidence is never parsed in M1) | — |
| Prompt injection | ✅ M5: spotlighting, verifier, scope re-checks, text-only output; HostileProvider and P1–P8 adversarial twins (integrity attacks detected, not prevented) | `test_ai_prompt.py`, `test_ai_verify.py`, `test_ai_postprocess*.py`, `ai_eval/test_ai_eval_invariants.py` |
| AI evidence citation accuracy (§14) | ✅ offline (FakeProvider 1.000, HostileProvider 0 violations); ⏳ live: none recorded | [M5 metric](#m5-metric-ai-evidence-citation-accuracy) |
| AI provider keys sealed, write-only, never exposed | ✅ M5 (own seal domain, analyst-only private key) | `test_ai_seal.py`, `test_ai_import_guard.py`, `test_ai_api_providers.py::test_sentinel_key_never_leaks` |
| Sandbox escape assumptions | ⏳ dynamic analysis milestone | — |
| Controlled PCAP dataset (normal web, DNS, TLS, beacon, DNS anomalies, port scans, suspicious HTTP) | ✅ synthetic, generated at test time with ground-truth labels | `apps/workers/pcap/dataset/` |
| Detection precision/recall, parsing success, latency | ✅ (synthetic) | `tests/evaluation/test_detection_quality.py` |
| Parser vulnerabilities (posture) | ✅ isolation + fuzz-lite (50 mutated captures and 50 mutated PE/ELF end cleanly); upstream fuzzing not replicated | `tests/evaluation/test_fuzz_lite.py` (both workers), `test_sandbox.py`, `test_parsers.py`, `test_hostile_output.py` |
| Malware dataset (benign PE, packed PE, suspicious imports, test signatures, EICAR; no real malware) | ✅ synthetic, generated at test time with labels | `apps/workers/static/samples/` |
| Malware detection precision/recall, parsing success | ✅ (synthetic) | `apps/workers/static/tests/evaluation/test_detection_quality.py` |
| Threat-intel API keys encrypted, never exposed to the browser | ✅ M4: sealed, write-only, never in reprs or error paths (full sentinel crawl: phase 7) | `test_ti_seal.py`, `test_ti_http.py`, `test_ti_api_integrations.py` |
| IOC enrichment: cache, rate limits, history, source attribution | ✅ M4 (fixtures and `ti-mock`; no live provider) | `test_ti_cache.py`, `test_ti_ratelimit.py`, `test_enrich_worker.py`, `test_ti_pipeline.py`, `ti-wording.test.ts` |
| SSRF (org-supplied MISP URL) | ✅ M4 | `test_ti_ssrf.py`, `test_ti_ssrf_resolve.py`, `test_ti_misp_worker.py` |
| IOC enrichment success metric | ⏳ M4 phase 7 (placeholder below) | `apps/api/tests/ti/test_enrichment_metric.py` |
| Professional reports with evidence citations (§1, §9) | ✅ M6: signed snapshot, `[Cn]` citations re-queried in scope with field hashes, offline verification | `test_report_citations.py`, `test_report_finalize.py`, `test_verify_report_script.py` |
| Case management: notes, IOC collections, status, ATT&CK, timeline (§10) | ✅ M6 | `test_case_notes.py`, `test_case_ioc_collections.py`, `test_case_status.py`, `test_case_attack.py`, `test_timeline_export.py` |
| Preserve analysis history (§10) | ✅ M6: append-only note versions, status events, report versions and citations (also for the owner) | `test_case_notes.py::test_version_rows_refuse_update_in_the_db`, `test_case_status.py::test_history_rows_refuse_mutation_by_the_owner_too`, `test_report_finalize.py::test_versions_and_citations_are_append_only` |
| Renderer isolation (untrusted text) | ✅ M6: seccomp, rlimits, deny-all fetcher, no egress | report-worker `test_sandbox.py`, `test_isolation.py`, `test_render_pdf.py` |
| "Do not send to AI / TI" and TLP | ✅ M6: API refusals and worker re-checks without provider calls | `test_share_policy.py`, `test_case_policy_api.py` |
| CSV / Markdown / HTML injection in exports and reports | ✅ M6 | `test_csv_safe.py`, `test_render_md.py`, `test_render_html.py`, `test_template_lint.py` |

## M2 metrics (synthetic dataset, local test rules)

| Metric | Value |
|---|---|
| Parsing success rate (valid captures) | 100% (8/8 scenarios) |
| Analysis latency per scenario | 1.2–1.4 s (ET Open adds ≈ 40 s rule loading per job) |
| beaconing / port_scan / dns_anomaly / suspicious_traffic | precision 1.0, recall 1.0 (TP 1 / 2 / 1 / 5, no FP, no FN) |
| False positives on benign scenarios | 0 |
| Fuzz-lite (50 mutants) | 50/50 terminal: 23 results, 22 unparseable, 3 unsupported format, 2 zeek_failed; 0 hangs/crashes |
| Ingest of 100 k flows | ≈ 20 s (validation ≈ 4 s, inserts ≈ 12 s) |

These are synthetic numbers: they show the detectors behave as specified, not real-world quality.
Regenerate them with `EVALUATION_OUT=/tmp/eval.json` in the worker test container. Worker failure rate is the fuzz-lite outcome distribution. IOC enrichment and AI citation accuracy are M4/M5 metrics.

## M3 metrics (synthetic sample set, test ClamAV DB)

| Metric | Value |
|---|---|
| suspicious_api / yara / pe_anomaly / capa / clamav / packer | precision 1.0, recall 1.0 (TP 7 / 7 / 7 / 3 / 2 / 1, no FP, no FN) |
| Parsing success, IOC recall | 1.0 |
| Benign samples | nothing above `info` |
| Slowest sample, every engine | 42.7 s |
| Fuzz-lite (50 mutated PE/ELF) | 50/50 terminal: 43 results, 7 with engine errors, 0 job failures; no tool process left behind |

Per-detector details and caveats: [MALWARE_ANALYSIS.md](MALWARE_ANALYSIS.md#synthetic-sample-set-and-quality). As for M2, these numbers show the detectors behave as specified, not real-world quality.

Run the static worker suite on its own (the test container uses a tiny ClamAV DB and test YARA rules):

```bash
docker compose --profile test run --rm --no-deps static-worker-test sh -c \
  "ruff check . && ruff format --check . && mypy static_worker tests samples && pytest -q -p no:cacheprovider"
```

Set `EVALUATION_OUT=/path.json` for the detector report and `FUZZ_OUT=/path.json` for the fuzz outcomes. After changing worker code, recreate the worker containers first (`docker compose --profile test up -d --force-recreate --no-deps static-worker static-worker-test`); Celery does not hot-reload.

## M4 threat intelligence suites

All run in `pnpm test:api` (api-test, `backend` only, no route out) unless noted. No test reaches a real provider: adapters use `httpx.MockTransport` and handcrafted fixtures (`tests/fixtures/ti/`), and the pipeline uses the `ti-mock` sink.

| Area | Tests |
|---|---|
| Sealing | `unit/test_ti_seal.py`: round trip, MISP key bound to its URL, wrong org / provider / kid / version / private key, flipped or truncated parts, no plaintext in reprs or errors, key bounds, private key file loading, worker startup check |
| Contracts and import guard | `unit/test_ti_contracts.py` (summary models: worst case under 16 KiB, control/bidi stripped, https-only permalinks; catalog; `ioc_key`; errors carry no body); `unit/test_ti_import_guard.py` (adapters, registry, `http` and `unseal` only in `app/workers/enrich*.py`, any import form) |
| Settings | `unit/test_config.py`: enrich role refuses JWT / MinIO / app Redis, private key file only for `enrich`, prod refuses the mock, the dev MISP flags and `dev-` seal keys; the prod enrich-worker env fixture checked by `scripts/check-enrich-env.mjs` |
| Normalization | `unit/test_ti_normalize.py`: refang, embedded IPv4 (6to4, NAT64, Teredo, mapped), special-use and `.arpa` names, URL query removal, excluded suffixes, per-provider eligibility, emails only to MISP |
| HTTP client | `unit/test_ti_http.py`: key only in the auth header and never in reprs, error bodies never read, status mapping, `Retry-After` forms, path allowlist before sending, body cap, gzip bomb with bounded memory, `trust_env` ignored, timeouts, hostile JSON → `bad_json` |
| Adapters | `unit/test_ti_provider_adapters.py`, `unit/test_ti_provider_fixtures.py` (every fixture of VT, AbuseIPDB, URLhaus, MalwareBazaar, OTX); `unit/test_ti_provider_live.py` (opt-in, below) |
| MISP and SSRF | `unit/test_ti_ssrf.py` (save-time syntax), `unit/test_ti_ssrf_resolve.py` (resolution, every answer global, pinning, Host/SNI, DNS pool busy), `unit/test_ti_misp.py`, `unit/test_ti_misp_worker.py` |
| ATT&CK | `unit/test_attack_index.py`, `unit/test_build_attack_index.py` (sha256 pin, deterministic output, tactics from the bundle), `integration/test_attack_route.py` |
| Schema | `integration/test_ti_schema.py`: tenant isolation, run index visibility, cross-org writes, append-only results (also for the owner), run transitions, key-version trigger, column grants, no DELETE on configs, constraints |
| Cache and limiter | `integration/test_ti_cache.py` (TTL table, freshness rules), `integration/test_ti_ratelimit.py` (bucket, daily cap, cooldowns, strikes, ceilings, broker outage) |
| Runs and worker | `integration/test_ti_runs.py` (planning, order, caps, skips); `integration/test_enrich_worker.py` (hit / not found, redelivery and duplicate slices, org mismatch, cache hit, faults, slice re-publish, waiting and resume, deadline, 429 past the deadline, fallback reaper, 401/403 with inline verify, daily quota, VT 429 strikes, limiter outage, lazy re-seal, verify task and dedupe) |
| API | `integration/test_ti_api_integrations.py`, `test_ti_api_runs.py`, `test_ti_api_results.py`, `test_ti_api_rbac.py`; the TI routes are also in the auto-enumerated `security/test_idor_routes.py` and `test_rls_coverage.py` |
| Broker ACL | `integration/test_enrich_acl.py`: `enrich` confined to `enrich*`, analyzers cannot touch it, `api` can publish |
| Pipeline | `integration/test_ti_pipeline.py`: seal → broker → real `enrich-worker-test` → httpx → `egress` → `ti-mock` |
| Network | `container/test_egress.py` (api-test: no default route, no internet); `container/test_enrich_network.py`, run **inside** `enrich-worker-test` by the gate: Postgres and the broker reachable, Redis / MinIO / API / gateway / web not |
| Web | `lib/ti.test.ts`, `lib/ti-wording.test.ts` (attributed, verdict-free templates), `components/ti/integration-card.test.tsx` |

Phase 7 adds the key-leak suite (a sentinel key absent from responses, audit rows, logs, Celery messages and reprs), the extended egress suite, the metric harness and `apps/web/e2e/threat-intel.spec.ts` (dev: the full flow against `mock`; prod: `mock` refused).

Run the enrich worker's own network test by hand:

```bash
docker compose --profile test run --rm --no-deps -e PYTHONDONTWRITEBYTECODE=1 enrich-worker-test \
  python -m pytest --noconftest -q -p no:cacheprovider tests/container/test_enrich_network.py
```

**Live provider smoke tests** (never in the gate; each costs quota): set `CYBERLAB_LIVE_TI=1` and `CYBERLAB_TI_KEY_<PROVIDER>` (`CYBERLAB_TI_KEY_ABUSECH` covers URLhaus and MalwareBazaar) and run `tests/unit/test_ti_provider_live.py` from a container with egress (the enrich worker's networks). No live run is recorded yet.

After changing TI code, recreate the workers (`docker compose --profile test up -d --force-recreate --no-deps enrich-worker enrich-worker-test`); Celery does not hot-reload.

## M4 metric: IOC enrichment success (resilience under synthetic faults)

600 lookups over the six real adapters' fixture handlers with a seeded fault mix (10% 5xx, 5% 429 — half with `Retry-After`, 2% malformed JSON, 1% timeout), a virtual clock and the real limiter. Success = (`ok` + `not_found`) / items that reached a provider, per provider; skipped and cached items are reported separately. Floors: ≥ 0.95 per provider and 0 ineligible values sent. With 3 retries the number mostly measures the retry and resume logic, not the providers (RT24). Harness: `apps/api/tests/ti/test_enrichment_metric.py` (marked `metric`) and `scripts/ti_eval.py`.

| Provider | Lookups | Success | Errors |
|---|---|---|---|
| VirusTotal | 100 | 1.000 | 0 |
| AbuseIPDB | 100 | 0.970 | 3 |
| URLhaus | 100 | 0.970 | 3 |
| MalwareBazaar | 100 | 0.990 | 1 |
| OTX | 100 | 0.970 | 3 |
| MISP | 100 | 0.970 | 3 |
| **All** | **600** | **0.978** | **13** |

- **Eligibility:** 245 ineligible values were submitted and skipped; 0 reached a provider.
- **Abandoned:** none (0 rate_limited, 0 quota_exhausted, 0 deadline).
- **Latency:** 729 requests; virtual p95 per request 1.08 s, p95 time to answer ~59 s (429 cooldowns). The pass took 29.5 virtual minutes, paced by VirusTotal's 4/min.
- **Cache (2nd pass):** 587 of 600 served from cache (0.978), i.e. every `ok` / `not_found` answer.
- Counts are identical from run to run (a retry that would cross a slice's end waits for the next slice instead of becoming an error); only slice counts and time to answer move with task timing. Full report: `plans/reports/ti-metric-261105.md`.

Live runs (`CYBERLAB_LIVE_TI=1`): none recorded.

## M5 AI analyst suites

All run in `pnpm test:api` unless noted. No test reaches a real provider: adapters replay handcrafted fixtures through `httpx2.MockTransport` / `httpx.MockTransport` (`tests/fixtures/ai/`), the worker tests use `ai-mock` and the in-process doubles (`tests/ai_doubles.py`), and the evaluation uses Fake / Hostile / Replay providers.

| Area | Tests |
|---|---|
| Contracts | `unit/test_ai_contracts.py`: provider schemas closed and inlined (Anthropic drops bounds, Gemini keeps array bounds), worst-case body fits 64 KiB, `coerce_caps`, label grammar, sanitize / defang / canonical forms, catalog and cost, availability (mock never in prod), run request shapes, metrics size, `context_sha256` covers only what is sent, FakeProvider determinism |
| Sealing and import guard | `unit/test_ai_seal.py` (own domain, AI ↔ TI ciphertexts never cross, wrong org / provider / kid / version, M4 key rules, no plaintext in reprs, startup check); `unit/test_ai_import_guard.py` (unseal, adapters, `ai.http` and SDKs only in the analyst worker; `sealbox_open` only in the two wrappers; no role holds both) |
| Settings | `unit/test_config.py`: analyst role refuses JWT / MinIO / app Redis / TI key; AI private and platform key files only for `analyst`; prod refuses mock, platform key, base-URL overrides, `dev-` kids and the dev public key; role-scoped kid guards; the rendered prod env of every role |
| Context | `unit/test_ai_context_fields.py` (allowlists, attribute grammar, no credential or hostile key, no query values or referrer, budget fill, stats never carry names), `unit/test_ai_context_pseudonymize.py` (internal vs public addresses, org CIDRs / suffixes, PTR names, usernames in paths, planted pseudonyms, transform order, truncation), `unit/test_ai_context_reduce.py`, `integration/test_ai_context_builder.py` (determinism, caps, priority, targets first, other orgs' rows never appear, incident children with shared pseudonyms) |
| Prompt, verifier, post-processing | `unit/test_ai_prompt.py` (pinned templates, spotlighting, outside-block allowlist, delimiter / canary collisions, repair hint), `unit/test_ai_verify.py` (every citation reason, anchor rule, claim rules, ATT&CK, timeline times, canary variants, flags, plain defanged body), `unit/test_ai_postprocess.py`, `unit/test_ai_postprocess_properties.py` (Hypothesis: display-safe, idempotent), `integration/test_ai_verify_db.py` (rows re-queried inside org and scope) |
| Providers and HTTP | `unit/test_ai_provider_anthropic.py`, `test_ai_provider_gemini.py`, `test_ai_provider_mock.py` (every fixture → its typed outcome, request shape on the wire, idle and total timeouts, allowlist), `unit/test_ai_http.py`, `unit/test_ai_registry.py`; `unit/test_ai_provider_live.py` (opt-in, below) |
| Schema | `integration/test_ai_schema.py`: isolation, run index visibility, cross-org writes and children, append-only (also for the owner), no DELETE grants, run transitions and identity, key-version trigger, column grants, constraints, indexes |
| Worker | `integration/test_analyst_worker.py` (happy path, lease and redelivery, deadlines, call cap, every typed outcome, timeouts charged, no session during a slow call, repair, canary leak, budgets and the day-key seed, platform key ceiling, limiter fail-closed, re-seal, incident map-reduce, digest reuse, resume, verify, no secrets in logs), `test_ai_lifecycle.py`, `test_ai_budget.py`, `test_ai_ratelimit.py`, `test_ai_mock_server.py` |
| API | `integration/test_ai_api_runs.py`, `test_ai_api_outputs.py`, `test_ai_api_settings.py`, `test_ai_api_providers.py`, `test_ai_api_rbac.py` (role matrix); every `/ai/*` route in `security/test_idor_routes.py` via `security/idor_cases_ai.py`; the timeline route via `idor_cases_reads.py` |
| Broker ACL and network | `integration/test_analyst_acl.py` (`analyst` confined, analyzers and `enrich` cannot touch it, `api` / `ingest` can publish); `container/test_analyst_network.py`, run inside `analyst-worker-test` (Postgres and the broker reachable, backend services not, not on `analysis`, `ai-mock` through `egress`, a default route, no API secrets or TI keys in its env); `container/test_egress.py` (api-test and the ingest worker resolve neither `ai-mock` nor the analyst workers); `py-worker-kit/tests/test_isolation.py::test_ai_hosts_are_not_reachable` (the analyzers neither); `container/test_enrich_network.py::test_it_holds_no_ai_private_key` (role separation) |
| Pipeline (phase 11) | `integration/test_ai_pipeline.py`: the API → broker → real `analyst-worker-test` → `ai-mock` → verifier → read model, on the default test lane (skipped in lanes 2–7): every pcap task completes with verified citations; an incident with two jobs reduces their digests (timeline times from the cited rows); `429-once` → `waiting` → resume → `completed` with the 429 not counted as a call; refusal with its category; `spend_limit`, `max_tokens`, `invalid_output` after one repair (malformed, schema); `echo` → `failed/canary_leak`, body withheld; `fabricate` → invalid citations, unsupported claims; `inject` → verdict flag, no link; tiny budget → `budget_exhausted`; AI turned off mid-run → `ai_disabled`; the deadline; `slow-5` under the 8 s test call timeout completes (RT7); `slow` beyond it → three calls seen by ai-mock, all charged, `provider_error` (RT2); a lost day key re-seeded from the DB (RT9); **outbound privacy**: the body ai-mock received holds no internal IP, hostname, username, URL query value or credential field with pseudonymization on. ai-mock mirrors what it received to the `ai_mock_state` volume, read-only in api-test (api-test cannot reach it) |
| Key leak (phase 11) | `integration/test_ai_key_leak.py` (the key ai-mock expects, set through the API: absent from every AI response and those embedding AI data, `audit_logs.details`, every AI table, the broker while a run waits, provider / client / error reprs; one run where ai-mock echoes the key in a 401 body); `scripts/check-ai-key-leak.mjs` reruns it with a fresh random key and scans the logs of the api, both analyst workers, ai-mock, ingest, Postgres and the broker (in `verify`) |
| Compose env (phase 11) | `scripts/check-analyst-env.mjs` (in `verify:prod`): dev, test and prod renders: no JWT / MinIO / app Redis / TI private key in any analyst worker; the AI private key and platform key files and secrets in no other service; prod `ENV=prod`, prod image, mock off, no platform key, no ai-mock; the prod env equals the `test_config.py` fixture |
| Evaluation | `tests/ai_eval/`: cases and golden files, harness, scoring, providers, replay, snapshot, invariant floors and live (below) |

The gate (`scripts/verify.mjs`) recreates `analyst-worker`, `analyst-worker-test` and `ai-mock` with the other workers, runs the analyst network test inside `analyst-worker-test`, the AI key-leak log scan, and on `--prod` `check-analyst-env.mjs` plus a probe that every prod analyst-worker replica is `running 0` with `ENV=prod`, `PROCESS_ROLE=analyst`, the mock off and no platform provider. It removes `AI_EVAL_LIVE` from its environment: live AI tests never run in the gate.

Run the analyst worker's network test by hand:

```bash
docker compose --profile test run --rm --no-deps -e PYTHONDONTWRITEBYTECODE=1 analyst-worker-test \
  python -m pytest --noconftest -q -p no:cacheprovider tests/container/test_analyst_network.py
```

**Live provider smoke tests** (never in the gate; they cost tokens): `tests/unit/test_ai_provider_live.py` from a container with egress, with a key file. `scripts/check_ai_models.py` lists the catalog ids through the Models APIs. Neither has been run with a key.

After changing AI code, recreate the workers (`docker compose --profile test up -d --force-recreate --no-deps analyst-worker analyst-worker-test`); Celery does not hot-reload.

## M5 metric: AI evidence citation accuracy

`scripts/ai_eval.py` prints the tables (it runs `tests/ai_eval` in api-test); details in [AI_ANALYST.md](AI_ANALYST.md#evaluation). 26 clean cases and 25 injected twins (payloads P1–P8), snapshots of the synthetic PCAP dataset and static samples taken through the real workers.

| Provider (label) | Runs | Citation accuracy mean / min | Unsupported mean | Invalid-ref mean | ATT&CK invalid proposed / shown | ATT&CK precision mean | Golden recall mean / min | Refused / invalid / error | ASR | Utility under attack | Floor violations |
|---|---|---|---|---|---|---|---|---|---|---|---|
| FakeProvider (**fake**, pipeline only; 26 clean cases, 31 case × task runs) | 31 | 1.000 / 1.000 | 0.005 | 0.000 | 0 / 0 | 1.000 | 0.895 / 0.000 (each case at its `fake_min_recall` floor) | 0 / 0 / 0 | n/a (clean cases) | n/a | **0** |
| HostileProvider (**hostile**, adversarial scripts; every case × 20 scripts) | 1220 | 0.772 / 0.111 | 0.241 | 0.154 | 488 / **0** | 0.361 | 0.048 / 0.000 | 0 / 122 / 0 | 0.290 (canary leak 84, external URL 28, forbidden verdict 20, severity downgrade 14: each caught and withheld, flagged or hidden) | 1.000 | **0** |
| Replay (**replayed**) | 0 | no cassettes committed | | | | | | | | | |
| Live Anthropic / Gemini (**live**) | 0 | **none recorded**: no key available locally | | | | | | | | | |

Recorded 2026-11-05 (`python scripts/ai_eval.py`, offline) over the cases regenerated that day from the real pipelines (`scripts/ai_eval_snapshot.py`: pcap-worker-test and static-worker-test on the synthetic dataset and samples, normalized rows only; `provenance.source = pipeline`). Tokens, cost and latency (p50 / p95) and the per-payload ASR (P1–P8) are only meaningful for a model and have no value until a live or replayed run exists. The HostileProvider "ASR" counts the attacks its scripts attempt, not attacks that got through: the floor violations column (0) is the gate.

CI floors are exact invariants (0 unverified or invalid citations counted as verified, 0 supported claims without a verified citation, 0 supported observed claims on trivial or unanchored quotes, 0 links persisted, 0 cross-org refs accepted, 0 invalid ATT&CK shown, 0 schema-invalid outputs persisted, every canary leak caught, every stripped code point removed). Live floors are reported, never gating: citation accuracy ≥ 0.95, unsupported ≤ 0.05, integrity ASR ≤ 0.05, utility ≥ 0.9. These offline numbers prove the verifier, not a model; the §14 metric has no live value yet.

## M6 reports and case management suites

The API suites run in `pnpm test:api` (api-test, the `reports-test` bucket with its lifecycle rule, the dev signing public key and a per-test key pair from `tests/report_helpers.py: use_signing_keys`). The renderer suites run **inside the report-worker image** (`report-worker-test`, test profile): `scripts/lane-test.sh <lane> --service report-worker-test pytest -q tests/` takes a lane slot from the same lock as api-test (about 1 GB). Shared fixtures: `apps/workers/report/tests/fixtures/{golden,hostile}_snapshot.json` (the hostile one carries `</style>`, `<img src=http://…>`, `url(file:///etc/passwd)`, U+202E, zero-width characters, 64 KiB strings, CSV formula cells and Markdown control sequences).

| Area | Tests |
|---|---|
| Contract | `unit/test_report_contract.py` (fixtures round-trip to identical canonical bytes, canonical form, UTC `Z`, floats refused, `BoundedText` truncation and `AnalystText` refusal, caps and totals, every cited number resolves, render units pinned on the golden snapshot, TLP constants, the OASIS STIX markings, manifest bytes, render messages), `unit/test_report_canonical.py`, `unit/test_vis_rules.py` (the committed table is the generated one) |
| Signing and verification | `unit/test_signing.py` (round trip, wrong kid / flipped byte, bad key files, no key material in errors or reprs, the dev pair), `unit/test_report_import_guard.py` (only `reports/signing.py` loads private keys), `unit/test_verify_report_script.py` (snapshot and PDF verify, tamper, wrong key or kid, manifest of another version, canonical form equals the contract), `integration/test_report_signing.py` |
| Share policy | `unit/test_share_policy.py` (TLP:RED implies both, reason order, 409 shape); `integration/test_share_policy.py` (resolution through jobs and evidence, other orgs never resolved, AI preview and run refused, the case builder skips excluded evidence with a stored, unrendered count, job enrichment refused, the analyst and enrich workers fail a blocked run without a provider call, manual lookups not checked); `integration/test_case_policy_api.py` (flags through the API, evidence share policy with its role rules, audit and untouched evidence row) |
| Case management | `integration/test_case_status.py`, `test_case_tlp.py`, `test_case_notes.py`, `test_case_ioc_collections.py`, `test_case_case_iocs.py`, `test_case_ioc_exports.py`, `test_case_attack.py`, `test_case_attack_suggestions.py`, `test_timeline_kinds.py`, `test_timeline_export.py`; `unit/test_csv_safe.py`, `unit/test_stix_export.py` |
| Reports (API) | `integration/test_report_drafts.py` (revision, TLP rule, archived case, discard, selections in scope, canary-leak runs not selectable, draft limits, viewer read-only), `test_report_snapshot.py` (sections, caps, trusted hashes, defang once, a 20 000-character Vietnamese summary kept whole, AI sections, numbering, preview stores nothing, deterministic build), `test_report_citations.py`, `test_report_cited_by.py`, `test_report_redaction.py` (no internal value survives `external`, one report-level map across AI runs), `test_report_finalize.py` (v1 then v2, append-only, publish failure, refused render, stale edit leaves an orphan, case TLP raised after the draft or during the build, profile rules, render budget and size limit before signing, rate limit), `test_report_storage.py` (exact version with retention, tampered object refused, content needs `evidence.read`) |
| Renders (API) | `integration/test_report_renders.py` (queue, index, audit, dispatch, presigned scope, dedupe, per-org and global caps, lost publish, permissions, rate limit, audited sandboxed download, tampered artifact refused, `test_end_to_end_pdf` through the real `report-worker-test`), `test_report_render_ingest.py` (token, org from the index, re-hash, typed failures, final renders immutable), `test_report_render_reaper.py`; `integration/test_report_acl.py` (broker user `report` confined) |
| Renderer (worker image) | `tests/test_sandbox.py` (every socket family but `AF_UNIX` and io_uring denied with `EACCES`, broker and MinIO unreachable from the subprocess, isolated Python, rlimits, OOM / CPU / size limits, kill-by-uid, prebuilt read-only font cache), `tests/test_isolation.py` (only `BROKER_URL`, no app services, TI or AI hosts, no egress or default route, broker ACL), `tests/test_render_pdf.py` (PDF/A-3a, attachments byte for byte, TLP on every page, identical bytes twice, page cap before writing, every fetch refused, no Ghostscript, dates from `finalized_at`), `tests/test_render_html.py`, `tests/test_render_md.py`, `tests/test_template_lint.py`, `tests/test_task.py` (the whole task with typed failures, cleanup, root-owned inputs, the embedded inputs are the signed bytes), `tests/test_skeleton.py`, `tests/test_render_budget.py` (a snapshot at the budget renders inside the sandbox; `REPORT_CALIBRATE=1` for the calibration sweep) |
| Security | every M6 route in `security/test_idor_routes.py` via `idor_cases_case.py`, `idor_cases_reports.py`, `idor_cases_renders.py`, `idor_cases_attack.py`; every M6 table in `integration/test_rls_coverage.py`; append-only tables in `test_append_only.py` |
| Web | `lib/reports.test.ts`, `lib/report-format.test.ts`, `lib/case.test.ts`, `lib/notes.test.ts`, `lib/ioc-collections.test.ts`, `lib/case-attack.test.ts`, `lib/tlp.test.ts`,`components/reports/report-builder.test.tsx`, `components/reports/report-view.test.tsx`, `components/notes/notes.test.tsx`, `components/ioc-collections/ioc-parts.test.tsx`, `components/investigations/case-overview.test.tsx`, `components/timeline/timeline.test.tsx`, `components/ai/policy-blocked.test.tsx` |

Run the renderer suite by hand (inside the image; `ruff` and `mypy` are in its dev dependencies):

```bash
docker compose --profile test run --rm --no-deps report-worker-test pytest -q -p no:cacheprovider tests/
```

`scripts/verify.mjs` and `pnpm test:workers` do not run the renderer suite yet: phase 9 adds it, with the M6 e2e (case → notes → collection → ATT&CK → report → finalize → PDF download → viewer with a valid signature) and the prod checks of the report-worker (`ENV=prod`, prod image, no signing key).

After changing renderer code, recreate the workers (`docker compose --profile test up -d --force-recreate --no-deps report-worker report-worker-test`); Celery does not hot-reload.

## M6 metric: report quality

Recorded during the build in the report-worker image; phase 9 records the gate run (citation resolution accuracy, render success rate, latency per format, deterministic-render rate, hostile-fixture escapes and the local veraPDF result) in `plans/reports/report-metric-YYMMDD.md` and here.

| Metric | Value |
|---|---|
| Render budget calibration (`REPORT_MAX_RENDER_UNITS` 450 000) | worst shape at the budget: 594 MiB peak RSS of the 768 MiB `RLIMIT_AS`, ≤ 214 pages |
| PDF render latency (golden snapshot) | p50 / p95 3.9 s |
| Deterministic renders (same image) | byte-identical PDF (`test_render_pdf.py::test_rendering_twice_gives_identical_bytes`, `::test_the_hostile_snapshot_renders_reproducibly`) |
| Hostile-fixture escapes | 0 (`test_render_html.py::test_hostile_payloads_are_inert_visible_text`, `test_render_md.py::test_the_hostile_document_has_no_links_images_or_html`) |
| veraPDF PDF/A-3a | local check only, not gating |
