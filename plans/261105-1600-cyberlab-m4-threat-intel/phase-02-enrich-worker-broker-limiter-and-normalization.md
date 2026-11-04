---
phase: 2
title: "Enrich worker broker limiter and normalization"
status: pending
priority: P1
effort: "14h"
dependencies: [1]
---

# Phase 2: Enrich worker broker limiter and normalization

## Overview
The trusted enrichment engine. It covers normalization and eligibility, the run-creation
service, the hardened HTTP client, the cache, the broker-side rate limiter and cooldowns, the
time-sliced run loop with lease, `waiting`/resume and deadline, the fallback reaper, verify,
the syntactic MISP URL check, and the `mock` provider with the `ti-mock` sink, so that the
whole path runs without real keys.

## Requirements
- **`threat_intel/normalize.py`** (pure): `normalize(type_hint, raw) -> Normalized | Skip(reason)`, with the rules in the plan.
  - `Normalized` carries `ioc_type` (`ipv4`, `ipv6`, `domain`, `url`, `md5`, `sha1`, `sha256`, `email`), `value_norm`, `ioc_key` and `notes` (`query_removed`, `refanged`).
  - IPs: unwrap IPv4-mapped, 6to4, NAT64 (`64:ff9b::/96`) and Teredo before the global check (RT13).
  - Domains: the special-use list from the plan, including `home`, `private`, `intranet`, `localdomain` and everything under `arpa` (RT13).
  - URLs: query string and fragment removed before `value_norm` and `ioc_key` (RT4).
  - `eligible(normalized, provider)` adds the provider's type support (from `catalog.py`) and the "never external" rules (email only to MISP and `mock`).
  - The mapping from M2/M3 `iocs.type` values to `IocType` is documented in a table.
  - Skip reasons: `not_global_ip`, `special_use_name`, `excluded_suffix`, `single_label`, `unsupported_type`, `invalid`, `has_userinfo`, `bad_scheme`, `too_long`.
- **`threat_intel/runs.py`** (service, no HTTP; phase 5 routes call it): `create_run(session, org, scope, *, job_id=None, values=None, providers, requested_by) -> RunCreated`.
  - Builds the plan in the caller's transaction: job → sample hashes first, then the job's distinct `iocs` by occurrence count, capped by `TI_MAX_IOCS_PER_RUN` (`truncated` in summary); manual → the given values (≤ 20).
  - Normalizes each value, applies the org's excluded suffixes and `eligible()` per provider, and inserts one `ti_run_items` row per eligible (IOC, provider) pair with its `seq`. Skips are counted in `summary.skipped` and returned as a per-value report.
  - Inserts `ti_enrichment_runs` and `ti_run_index` (`dispatched_at = now()`); no items → no run.
  - `dispatch(run)` sends `ti.enrich` after the commit with the same timeout and limiter as `dispatch.send()`; a failure is logged and left to `ti.resume`.
- **`threat_intel/ssrf.py`** (syntactic half; phase 4 adds resolution and pinning): `validate_base_url(url) -> ValidatedBase` — https only, no userinfo / query / fragment, port 443 or `TI_MISP_ALLOWED_PORTS`, IDNA host, a literal IP must pass the IP rules, a name must not be special-use, path prefix normalized (≤ 256 characters). Returns `base_url_norm` (used in the seal AAD). No DNS (RT5).
- **`threat_intel/http.py`:**
  - `ti_client(provider, *, transport=None, pinned=None)` → `httpx.AsyncClient`;
  - `trust_env=False`, `follow_redirects=False`, timeouts (3 / 10 / 20 s), a fixed User-Agent `CyberLab-TI/<version>`;
  - **the key is attached per request by `KeyAuth(header, SecretStr)`, an `httpx.Auth` subclass whose `repr` is redacted; it is never put in `client.headers`** (httpx masks only `Authorization` in reprs) (RT11);
  - an `allowed_paths` check on every request, made by an event hook (raises `PathNotAllowed`);
  - `fetch_json(...)` streams the body with a cap (1 MiB; MISP 2 MiB) and maps failures to `ProviderError(kind)`: `timeout`, `oversize`, `bad_json` (including `RecursionError`, the int-digit limit and non-finite numbers, RT19), `http_5xx`, `redirect`, `auth`, `rate_limited(retry_after)`, `not_found`;
  - provider error bodies are never logged or stored (some echo the key); only the kind and HTTP status are kept (RT11);
  - the `httpx` and `httpcore` loggers are set to WARNING; headers are never logged.
- **`threat_intel/ratelimit.py`** (on the broker, RT2):
  - a Lua token bucket per (provider, org) per minute plus a daily counter (UTC key, expires after 48 h), keys `{prefix}enrich.ti:{rl|day|cool}:…`;
  - cooldown keys;
  - `Retry-After` parser (delta seconds or an HTTP date; clamped to 1–3600 s; malformed → default backoff);
  - effective limits = min(org `limits`, settings ceiling);
  - a broker error fails closed (`LimiterUnavailable` → the run goes `waiting`, resume in 30 s) (RT8).
- **`threat_intel/cache.py`:** `fresh_result(session, org, provider, ioc_key)` returns the newest unexpired `ok` / `not_found` row (`expires_at > now()` in SQL, DB clock). TTL table as in the plan, `not_found` ¼ (hashes ≤ 6 h).
- **`threat_intel/providers/registry.py`:** provider name → adapter module path, imported lazily; phases 3 and 4 add only their modules, never edit the registry.
- **`app/workers/enrich_app.py`** (phase 1 config) and **`app/workers/enrich.py`.**
- **Task `ti.enrich {run_id, org_id}`** — one time slice (RT6):
  1. Look the run up in `ti_run_index` (system session): it must exist, its org must match the message, and its state must be queued, waiting or running. Otherwise the message is dropped and logged (ids only).
  2. Take the lease: `UPDATE ti_run_index SET lease_until = now() + 60 s, lease_owner = :token WHERE run_id = :id AND (lease_until IS NULL OR lease_until < now())`. No row → another slice holds it; exit (RT8).
  3. Past `deadline_at` → finalize (step 9) with pending items `abandoned/deadline`.
  4. Mark the run `running`.
  5. Process `pending` items in `seq` order until `TI_SLICE_S` elapses (asyncio timeout; the solo pool ignores Celery time limits), renewing the lease every 20 s:
     - a cache hit → item `cached` with the hit's `result_id` (RT10);
     - otherwise the cooldown and bucket checks, then unseal the key (lazy re-seal under the active kid, same `key_version`), then `provider.lookup`, then `INSERT … ON CONFLICT DO NOTHING` into `ti_results` and item `done` with its `result_id`;
     - per-provider semaphore ≤ 4, global ≤ 16.
  6. A daily cap reached → that provider's pending items `abandoned/quota_exhausted`, cooldown until 00:00 UTC.
  7. A 401/403 → run `provider.verify` once inline (RT23): a failed verify sets `verify_status=invalid`; either way the pair gets an `auth_failed` row and the provider's remaining items `abandoned/auth_failed`.
  8. Work left at the end of the slice: if a token is ready within 2 s, re-publish `ti.enrich` to the tail of the queue (`dispatched_at = now()`); otherwise `waiting` with `resume_at` = the earliest ready time. Release the lease.
  9. Nothing pending: under `FOR UPDATE` on the run (already final → no-op), `completed` if every item is `done` with `ok` / `not_found` or `cached`, `failed` if no item reached a provider, otherwise `partial`. `summary` holds per-provider counts (`ok`, `not_found`, `error`, `auth_failed`, `cached`, `abandoned_rate_limited`, `abandoned_quota_exhausted`, `abandoned_deadline`, `abandoned_auth_failed`, `skipped_*`) and latency p50/p95.
  10. A 429 whose cooldown ends after the deadline → the provider's pending items `abandoned/rate_limited`.
  - Task return values are always `None` (Celery logs them).
- **Task `ti.resume`** (sent by ingest-beat every 30 s, `expires` 25 s): from `ti_run_index`, re-sends `ti.enrich` for runs that are `waiting` with `resume_at <= now()`, or `queued`/`running` with an expired lease and `dispatched_at` older than 2 minutes, and sets `dispatched_at = now()` for each (RT8). Batch ≤ 100.
- **Fallback reaper** (ingest-worker reaper, extended; RT9): runs whose lease expired and whose `deadline_at` passed more than 10 minutes ago are finalized exactly as in step 9 (pending items `abandoned/deadline`) under `FOR UPDATE` on the run and its index row. It writes no `ti_results` rows. Audit `ti.run_deadline`.
- **Task `ti.verify {org_id, provider}`:** for MISP first re-validates and resolves the URL (phase 4); calls `provider.verify`, then sets `verify_status` (`valid` / `invalid` / `error`), `verified_at` and `last_error_code`. Audit `integration.verified` / `integration.verify_failed` with a NULL actor.
- **`mock` provider and `infra/ti-mock/server.py`:**
  - the IOC value selects the behaviour (`hit.example.com`, `notfound.example.com`, `ratelimit-ra.example.com`, `ratelimit.example.com`, `err500.example.com`, `slow.example.com`, `big.example.com`, `redirect.example.com`, `badjson.example.com`, plus hashes of a fixed pattern); any other value is a deterministic not-found, so a job run against `mock` alone ends `completed` unless a fault value is present;
  - `X-Mock-Key` is checked against `TI_MOCK_EXPECTED_KEY`;
  - the mock host bypasses the public-IP rule only through the catalog's `dev_only` flag. That flag is unavailable in prod (an import-time assert plus `_prod_guards`).

  These names are reserved for the mock. `normalize` returns `Skip(special_use_name, value_norm=…)` for them as usual, and `eligible()` lets only the `mock` provider accept a `special_use_name` skip under `example.com`. Every real provider still refuses them, and a test asserts that.

## Implementation Steps
1. `normalize.py` with table-driven unit tests:
   - refang variants;
   - `100.64.0.1`, `::ffff:10.0.0.1`, `2002:c0a8:0101::1`, `64:ff9b::a00:1`, `2001:db8::1`, `169.254.169.254`, `0.0.0.0`;
   - IDN (`bücher.de` → `xn--bcher-kva.de`), trailing dots, `.local`, `.home.arpa`, `5.1.168.192.in-addr.arpa`, `nas.home`, single labels;
   - URLs with userinfo, ftp, and `?token=…#frag` (stripped, `query_removed`);
   - wrong hash lengths and upper-case hashes;
   - email routing.
2. `ssrf.validate_base_url` with unit tests (http, userinfo, query, disallowed port, decimal/octal IP literal `2130706433`, special-use host).
3. `http.py` and `ratelimit.py` with MockTransport and broker-db-1 tests:
   - body cap, redirect refused, `trust_env` ignored (`HTTPS_PROXY` set in the test env), unlisted path refused, deep-nesting JSON → `bad_json`;
   - `repr(client)`, `repr(request)`, `str(exc)` never contain the sentinel key;
   - bucket refill;
   - daily cap rollover at 00:00 UTC (frozen clock);
   - `Retry-After` forms;
   - broker unavailable → `LimiterUnavailable`.
4. Cache module with TTL tests, including that errors are never returned as hits.
5. `runs.create_run` with tests: job plan order and cap, manual ≤ 20, skips counted, excluded suffixes, no eligible item → no run.
6. Celery enrich tasks, the reaper extension and the beat entry. Tests with an in-process fake provider:
   - redelivery idempotency and a concurrent duplicate slice (lease) → no duplicate provider call;
   - an org mismatch is dropped;
   - slice budget → re-publish; a token far away → waiting/resume;
   - `ti.resume` does not re-send a queued run dispatched < 2 min ago;
   - deadline → partial; fallback reaper on a run with an expired lease; worker finalize after reaper = no-op;
   - 401 with failing inline verify → invalid; 403 with passing verify → still valid;
   - quota → `abandoned/quota_exhausted`;
   - cache hit → item `cached` with `result_id`;
   - the summary counts.
7. The `mock` adapter and the `ti-mock` server. A pipeline test (`test_ti_pipeline.py`) seals a key through the real code, creates a run through `runs.create_run`, sends a real `test.enrich` task to `enrich-worker-test`, and checks (the test sends `test.` `ti.resume` itself, because no test beat runs):
   - the hit, not-found and 429 → waiting → resume outcomes;
   - a wrong key → `auth_failed` and `verify_status=invalid`.

## Success Criteria
- [x] No ineligible value ever reaches a transport (asserted on every MockTransport request in the suite through a shared fixture), including `.arpa` names, embedded private IPv4 and URL query strings. — `tests/ti_helpers.py::SafeTransport` / `assert_eligible_request`; `test_ti_normalize.py::test_non_global_ips_are_skipped`, `test_special_use_names_are_skipped`, `test_url_query_and_fragment_are_removed`; metric: 0 of 245 ineligible values sent (5376596, a21c9d2).
- [x] A pipeline run through `enrich-worker-test` and `ti-mock` ends `completed` / `partial` exactly as expected; a redelivered or duplicated message writes no duplicate rows and makes no duplicate provider call. — `test_ti_pipeline.py::test_hit_not_found_outage_and_cache`, `test_deadline_ends_partial`; `test_enrich_worker.py::test_redelivery_and_concurrent_duplicates_make_no_extra_calls` (5376596).
- [x] A long run yields the worker every `TI_SLICE_S`; rate-limited runs resume without Celery ETA; a lost message is recovered by `ti.resume`; past-deadline runs end `partial`. — `test_enrich_worker.py::test_slice_budget_republishes_to_the_tail`, `test_token_far_away_waits_and_resumes`, `test_resume_does_not_resend_recent_queued_runs`, `test_deadline_ends_partial`; `test_ti_pipeline.py::test_429_waits_then_resumes` (5376596, d3a93e1).

## Implementation Notes (2026-11-05)
- **Commits:**
  - 5376596: phase 2, plus the phase-1 review fixes;
  - 7abb484: phase-2 review fixes;
  - 913023d: the lane and renewer review fixes, which landed with phase 4;
  - d3a93e1: retries carried over to the next slice.
- **Slice loop** (`app/workers/enrich.py`):
  - One `ti.enrich` is one slice of at most `TI_SLICE_S` (20 s), enforced with asyncio timeouts.
  - Lease: `lease_until = now() + 60 s`, renewed every 20 s.
  - Work left: the run is re-published to the queue tail if a token is ready within 2 s, otherwise it goes `waiting` with `resume_at`.
  - The run's org in `ti_run_index` must match the message (`test_org_mismatch_and_bad_messages_are_dropped`). Duplicate slices exit (`test_redelivery_and_concurrent_duplicates_make_no_extra_calls`).
- **Lanes (review, 913023d):**
  - One lane per provider in an `asyncio.TaskGroup` (not `gather`), with semaphores of 4 per provider and 16 overall.
  - An item failure is recorded and the lane goes on. A failure that cannot be recorded halts the slice, and a lane that raises cancels its siblings.
  - `renew_forever` never raises.
  - Tests: `unit/test_ti_misp_worker.py`, `test_the_lease_renewer_never_raises`.
- **Retries:** 5xx, timeouts and transport errors get 3 attempts with full-jitter backoff (0.5 s base, 4 s cap), then an `error` row.
  - **d3a93e1:** if a retry's backoff would cross the slice end, the item stays `pending` and its attempt count is carried in worker memory (bounded), instead of becoming a final `error`.
  - Tests: `test_5xx_near_the_slice_end_stays_pending_for_the_next_slice`, `test_carried_over_retries_still_end_after_three_attempts`, `test_carried_over_item_still_ends_partial_at_the_deadline`.
- **Resume, deadline and reaper:**
  - `ti.resume` runs from ingest-beat every 30 s (batch ≤ 100). It re-sends `waiting` runs past `resume_at`, and `queued` / `running` runs with an expired lease dispatched more than 2 minutes ago, and bumps `dispatched_at` (`test_resume_does_not_resend_recent_queued_runs` also covers re-sending a lost message).
  - Deadline (1800 s) at every slice: `test_deadline_ends_partial`, `test_deadline_with_nothing_attempted_fails`, `test_429_past_the_deadline_abandons_rate_limited`.
  - The reaper fallback acts 10 minutes past the deadline under `FOR UPDATE`, audits `ti.run_deadline` and writes no result rows (`test_fallback_reaper`).
- **401/403:**
  - The provider's verify runs inline (RT23): `test_401_with_failing_verify_marks_invalid`, `test_403_with_passing_verify_stays_valid`.
  - Lazy re-seal under the active kid at the same version (`test_lazy_reseal_under_the_active_kid`).
  - `ti.verify` is deduped per (org, provider, key_version) for 60 s through `enrich.ti:verify:*` (`test_duplicate_verify_of_the_same_key_is_skipped`).
- **Limiter** (`ratelimit.py`, broker keys `{prefix}enrich.ti:{rl,day,cool,strikes,verify}:*`):
  - Lua token bucket; a UTC daily counter with a 48 h TTL; cooldowns that can only be extended.
  - A broker outage raises `LimiterUnavailable`: no provider call, and the run waits 30 s (`test_broker_unavailable_fails_closed`, `test_limiter_outage_fails_closed`).
  - Effective limits are capped by the ceilings (`test_effective_limits_never_exceed_the_ceiling`).
- **`Retry-After`:** delta seconds or an HTTP date, clamped to 1–3600 s. **Review:** only ASCII digits count, so Unicode digits are malformed and get the default backoff (`test_retry_after_non_ascii_digits_are_malformed`, `test_429_with_unparsable_retry_after_gets_the_default_backoff`).
- **HTTP client** (`http.py`), **review: decompression bomb (7abb484):**
  - Requests send `Accept-Encoding: identity`. A gzip or deflate body is inflated incrementally, with the 1 MiB / 2 MiB cap applied to the inflated bytes; any other coding is refused. A 256 MiB bomb stays under 4 MiB (`test_gzip_bomb_is_refused_with_bounded_memory`, `test_inflater_never_produces_more_than_the_cap_plus_one`).
  - The allowlist also checks scheme and port.
  - Strict JSON: depth ≤ 64, integers ≤ 40 digits, no NaN; any failure is `bad_json`.
- **Normalization** (`normalize.py`, pure), beyond the plan:
  - more refang forms (`fxp`, `{.}`, `(dot)`, `(@)`, `[at]`) and a 2048-character cap (`too_long`);
  - IPv4-compatible `::/96` and NAT64 local-use `64:ff9b:1::/48` are checked;
  - `alt` and `example.com/net/org` count as special-use names.
- **Review: hex-IPv4 eligibility:** a host whose last label is numeric or `0x`-hex is never a name, because WHATWG parses `10.0.0.0x1` and `misp.123` as IPs (`test_numeric_last_labels_are_never_names`, `test_hex_looking_labels_that_are_names`).
- **Runs, cache and SSRF syntax:**
  - `integration/test_ti_runs.py`: `test_job_plan_order_and_cap`, `test_nothing_eligible_creates_no_run`, `test_excluded_suffixes`, `test_dispatch_publishes_ids_only`.
  - `integration/test_ti_cache.py`: `test_ttl_table`, `test_fresh_result_rules` (DB clock; errors are never hits).
  - `unit/test_ti_ssrf.py` for `validate_base_url`.
- **Mock provider:** `providers/mock.py` (6000/min) plus `infra/ti-mock/server.py`. Only `mock` accepts special-use names, and only under `example.com` (`test_only_mock_accepts_its_example_com_names`, `test_skips_never_become_eligible_for_real_providers`).
- **Wire-level eligibility:** `tests/ti_helpers.py::SafeTransport` re-normalizes every IOC that reaches a MockTransport and fails on any ineligible value or query string.
  - It is used by `test_enrich_worker.py`, `test_ti_http.py` and `test_ti_key_leak.py`.
  - The phase-7 metric harness re-checks every request: 0 of 245 ineligible values were sent.
- **Pipeline** (`integration/test_ti_pipeline.py`, the real `enrich-worker-test` → `egress` → `ti-mock`): `test_hit_not_found_outage_and_cache`, `test_429_waits_then_resumes`, `test_deadline_ends_partial`, `test_wrong_key_is_auth_failed_and_invalid`, `test_verify_task`.
- **Other review fixes (7abb484):**
  - SQLAlchemy `hide_parameters=True` (`core/db.py`), so a failed statement never puts bound values into a Celery traceback;
  - keys with whitespace or non-printable characters are refused at seal time;
  - protocol errors never carry the key;
  - permalinks are ASCII-only.
- **Deviations:** no Celery countdown or ETA anywhere (as planned); the VirusTotal 429-strike quota escalation was added in 913023d; `scripts/check-enrich-env.mjs` joined the gate in this phase.
