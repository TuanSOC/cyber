# Testing

## Commands

| Command | What |
|---|---|
| `pnpm verify` | everything below + Playwright, from the dev stack |
| `pnpm verify:prod` | `verify` + prod stack health, headers, HSTS |
| `pnpm test:api` | API test suite (real Postgres, Redis, MinIO; no mocks of analysis or storage) |
| `pnpm lint:api` | ruff, format check, mypy `--strict` |
| `pnpm lint:web` | Next typegen + tsc, eslint, vitest |
| `pnpm e2e` | Playwright golden path against the running stack (`pnpm e2e --prod` for the prod-like stack) |
| `pnpm gen:contracts` | Regenerate the OpenAPI contract and TS types (`verify` fails on drift) |

To prove the gate from empty volumes without touching dev data, stop the dev stack (`pnpm down`, volumes kept) and run `COMPOSE_PROJECT_NAME=cyberlab-clean pnpm verify`, then `COMPOSE_PROJECT_NAME=cyberlab-clean docker compose down -v`.

Test isolation: the API suite uses `cyberlab_test`, Redis db 1 and the `evidence-test` bucket; the harness refuses any database not ending in `_test` and Redis db 0, truncates tables and flushes Redis around each test, and purges the test bucket (including locked versions) at session start/end.

## Current results

- API: ~300 tests (unit, integration, security; pytest prints the exact count). Typical run ≈ 75–100 s.
- Web: unit tests (redirect safety), typecheck, lint, production build.
- E2E: 1 Playwright scenario, run against dev (`pnpm e2e`) and the prod-like stack over TLS (`pnpm e2e --prod`, part of `verify:prod`): register → create case → upload (hash checked against a locally computed SHA-256) → verify → custody chain → sign out, with no console errors.
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
| Malware scanning of uploads | ⏳ M3 (ClamAV) | — |
| Data retention / expiry policy | ⏳ later (only the 30-day governance lock exists) | — |
| Backup / restore | ⏳ later | — |
| Parser vulnerabilities | ⏳ M2+ (no parsers yet; evidence is never parsed in M1) | — |
| Prompt injection | ⏳ M5 (AI analyst) | — |
| Sandbox escape assumptions | ⏳ dynamic analysis milestone | — |
| Anonymized PCAP / malware datasets, detection precision/recall | ⏳ M2 / M3 | — |

## Metrics to collect from M2

Parsing success rate, analysis latency, detection precision/recall, IOC enrichment success, AI citation accuracy, worker failure rate (per `requirement.txt` §14).
