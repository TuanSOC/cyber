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
- Web: unit tests (redirect safety, CSP builder, pcap and static result helpers, TI wording and helpers), typecheck, lint, production build.
- E2E: Playwright specs, run against dev (`pnpm e2e`) and the prod-like stack over TLS (`pnpm e2e --prod`, part of `verify:prod`), with no console errors:
  - `smoke.spec.ts`: register → create case → upload (hash checked against a locally computed SHA-256) → verify → custody chain → sign out;
  - `pcap.spec.ts`: capture upload → automatic PCAP analysis → findings;
  - `malware.spec.ts`: synthetic PE upload → automatic static analysis (`full`) → Malware Lab results and report;
  - `csp.spec.ts`: fresh nonce per HTML response, strict policy on the API, pages hydrate, injected markup without the nonce is blocked.
- Observed once during development: a `pnpm verify` run had 13 API test failures (CSRF/auth-event assertions) right after the stack was recreated; not reproduced in later runs (including from fresh volumes). Tracked as a possible flake — rerun before investigating.

### E2E side effects

E2E runs against the real stack, not the test database. Each run:
- clears the per-IP register rate-limit keys (`rl:register:*`) in that stack's Redis, so repeated runs do not hit 429;
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
| Prompt injection | ⏳ M5 (AI analyst) | — |
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
| OTX | 100 | 0.980 | 2 |
| MISP | 100 | 0.970 | 3 |
| **All** | **600** | **0.980** | **12** |

- **Eligibility:** 245 ineligible values were submitted and skipped; 0 reached a provider.
- **Abandoned:** none (0 rate_limited, 0 quota_exhausted, 0 deadline).
- **Latency:** 730 requests; virtual p95 per request 1.08 s, p95 time to answer 59.9 s (429 cooldowns). The pass took 29.5 virtual minutes, paced by VirusTotal's 4/min.
- **Cache (2nd pass):** 588 of 600 served from cache (0.980), i.e. every `ok` / `not_found` answer.
- Results vary by about ±1 item between runs (task timing). Full report: `plans/reports/ti-metric-261105.md`.

Live runs (`CYBERLAB_LIVE_TI=1`): none recorded.
