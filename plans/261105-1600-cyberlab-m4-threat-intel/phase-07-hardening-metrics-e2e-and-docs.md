---
phase: 7
title: "Hardening metrics e2e and docs"
status: pending
priority: P1
effort: "10h"
dependencies: [3, 4, 5, 6]
---

# Phase 7: Hardening metrics e2e and docs

## Overview
Close M4: the isolation and leak suites end to end, the "IOC enrichment success" metric under a
seeded fault mix, the e2e flow on the `mock` provider (and the refusal in prod), the verify
gate, the docs, and the plan notes.

## Requirements
- **Egress suite** (no real internet anywhere; `ti-mock` is the sink):
  - api-test, ingest-worker and the analyzer test containers have no default route and cannot resolve or connect to `ti-mock`. This is added to the kit's `test_isolation.py` for the analyzers and to `apps/api/tests/container/test_egress.py` for api-test;
  - api-test cannot resolve a public name (`example.org`); if the Docker engine forwards it anyway, the test records it and THREAT_MODEL lists the DNS channel as a residual (RT22);
  - `enrich-worker-test` has a default route through `egress`, reaches `ti-mock`, and is not on the `analysis` network (cannot resolve `pcap-worker-test`);
  - the enrich-worker environment (dev and prod configs, `docker compose config`) holds no `JWT_SECRET`, `MINIO_*` or `REDIS_URL`, and the prod one has `ENV=prod` and the prod image (RT2, RT3);
  - the pipeline test proves the full path (seal → worker → httpx → sink).
- **Key-leak suite:** a sentinel key set through the API is absent from:
  - every API response (crawl of all TI routes and the generic routes that embed TI data);
  - `audit_logs.details`;
  - api, enrich-worker and ingest-worker logs captured during the pipeline test (`docker compose logs` scan in the test script), including a run where the mock echoes the key in a 401 body;
  - `repr` / `str` of the client, request, auth object, `SealedKey` and every `ProviderError` (RT11);
  - Celery message bodies on the broker (inspected through the test broker user while a run waits);
  - `ti_results.summary`;
  - error envelopes for failed PUTs.
- **Security regression:**
  - RLS coverage and IDOR enumerators include the TI tables and routes;
  - a broker ACL test for `enrich`;
  - the AST import guard (adapter, registry, http and unseal modules only in the enrich worker, any import form);
  - settings and prod-guard tests (`TI_MOCK_ENABLED`, `TI_MISP_ALLOW_PRIVATE`, `TI_MISP_INSECURE_TLS`, a `dev-` active kid in prod, a private-key file in a non-enrich process, JWT/MinIO/Redis settings in the enrich process);
  - a MISP key sealed for one `base_url` cannot be used after the URL changes (DB-level swap test);
  - normalization property tests (hypothesis): no non-global IP (including 6to4/NAT64/Teredo-embedded), special-use or `.arpa` name, and no URL with a query string, is ever sent as such.
- **Metric "IOC enrichment success":** `apps/api/tests/ti/test_enrichment_metric.py` (marked `metric`) plus `scripts/ti_eval.py` to print the table.
  - 600 lookups over the six real adapters' fixture handlers, seeded RNG. Fault mix: 10% 5xx, 5% 429 (half with Retry-After), 2% malformed JSON, 1% timeout. Clock and sleep are virtual, and the limiter and time slices are exercised.
  - Success = (`ok` + `not_found`) / items that reached a provider, per provider. Skipped values and `cached` items are excluded and reported separately.
  - A second pass measures the cache hit rate. Also reported: the shares of `abandoned` items by reason (rate_limited, quota_exhausted, deadline) and p95 latency (virtual).
  - Floors: success ≥ 0.95 per provider, and 0 ineligible values sent. The results go into TESTING.md, labelled "resilience under synthetic faults": with 3 retries the floor mostly measures the retry and resume logic, not the providers (RT24). When live keys were used (`CYBERLAB_LIVE_TI=1`), the live run summaries are recorded next to it.
- **E2E** `apps/web/e2e/threat-intel.spec.ts`:
  - **dev:**
    1. register → org settings → Integrations → acknowledge the `mock` terms → configure it with the test key → verify becomes `valid`;
    2. upload the e2e pcap → pcap job → IOCs tab → Enrich → the run passes through `waiting` (a `ratelimit-ra` value with `Retry-After: 1`) and ends exactly `completed` within 90 s (one beat resume) → chips "reported by Test provider";
    3. enrich again → the items show as cached; open history;
    4. the lookup page with `10.0.0.1` (skipped, private), `https://hit.example.com/a?token=x` (query removed) and `hit.example.com` (result);
    5. the Malware job shows ATT&CK chips with names;
    6. no console errors; no key value in the page HTML (`page.content()` scan).
  - **prod e2e:** the catalog shows `mock` unavailable and `PUT` returns 422. The flow is skipped with a clear reason. The gate also asserts that the prod `enrich-worker` reports `ENV=prod`.
  - `scripts/e2e.mjs` starts `ti-mock` (profile `e2e`) and passes `TI_MOCK_EXPECTED_KEY` to it. The e2e pcap dataset gets a few IOC values aimed at the mock (generated, not committed).
- **Verify gate** (`scripts/verify.mjs`):
  - recreate `enrich-worker` and `enrich-worker-test` in the worker-reload step;
  - add the egress and container tests to `pnpm test:api` (or a new `pnpm test:enrich`);
  - live TI tests are never in the gate.
- **Docs:**
  - new **`docs/THREAT_INTEL.md`:**
    - providers table (types, endpoints, auth header, limits, verified quotas, ToS notes, permalinks);
    - normalization and eligibility rules; cache and TTLs; rate limits, waiting/resume, deadline;
    - key sealing and rotation runbook (sealing key and provider key); MISP SSRF rules and dev flags;
    - ATT&CK index build and update procedure plus the notice;
    - verdict-free presentation policy; the metric table; limitations;
  - **ARCHITECTURE:** enrich-worker, networks diagram with `egress`, the `backend` internal note;
  - **DATABASE:** the 0009 tables and grants;
  - **API:** TI routes and permissions;
  - **THREAT_MODEL:** new trust boundary "enrich-worker ↔ internet"; STRIDE rows for key theft (including MISP URL redirection, bound by AAD), SSRF, provider response injection, quota exhaustion, privacy leakage (URL queries, internal names), cross-org cache inference, worker starvation; residuals (unrestricted egress of the enrich-worker, its app DB role, a possible DNS channel from internal networks, provider text untrusted for M5, third-party disclosure of investigated IOCs, no TLP labels, ToS);
  - **TESTING:** M4 suites and metric; **DEPLOYMENT:** seal keys (dev pair, prod keygen, `chown 10001`, rotation runbook with the one-off enrich-worker container), the enrich-worker prod override, `backend` internal check table, MinIO console change, `UV_NO_SYNC`;
  - ROADMAP (M4 done, deferrals), README, `.env.example`.
- **Plan notes:** every phase file gets "Implementation Notes", and the success criteria are ticked only with evidence (a test name or a gate log).

## Implementation Steps
1. The egress and key-leak suites, and the security regression additions.
2. The metric harness and `scripts/ti_eval.py`; record the numbers.
3. The e2e spec, the `scripts/e2e.mjs` changes and the dataset additions; run them in dev and prod.
4. The verify gate update; `pnpm verify:prod`.
5. Docs; the reviewer pass on the enrich-worker, seal, SSRF and API (no open High findings); the plan notes.

## Success Criteria
- [ ] `pnpm verify:prod` green (dev e2e runs the TI flow; prod e2e asserts the mock is refused).
- [ ] Egress: only enrich-worker reaches the sink; api, ingest and the analyzers have no route; the enrich-worker holds no JWT, MinIO or app-Redis secret and runs `ENV=prod` in prod.
- [ ] Sentinel key absent everywhere listed above.
- [ ] Enrichment success ≥ 0.95 per provider under the fault mix, recorded in TESTING.md.
- [ ] Reviewer passes with no open High findings; docs updated, including the new THREAT_INTEL.md.
