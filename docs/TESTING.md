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
- Web: unit tests (redirect safety, CSP builder, pcap and static result helpers), typecheck, lint, production build.
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
