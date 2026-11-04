# IOC enrichment success: resilience under synthetic faults

Generated 2026-11-04 19:42 UTC by `python scripts/ti_eval.py --write` (test
`apps/api/tests/ti/test_enrichment_metric.py`, marker `metric`).

What this measures (RT24): 600 lookups, 100 per real adapter (VirusTotal, AbuseIPDB, URLhaus,
MalwareBazaar, OTX, MISP), through the real enrich-worker slices, broker limiter, retries,
cooldowns and `waiting`/resume path. The real adapters parse the committed fixture bodies
(`apps/api/tests/fixtures/ti/manifest.json`). Faults are drawn from a seeded RNG, and the clock
is virtual (provider latency, timeouts, backoff, cooldowns and beat resumes take no real time).
With 3 attempts per lookup, the 0.95 floor mostly measures the retry and resume logic, not the
providers. No live keys were used, so no live-run summary is recorded here.

Pass 1: 600 lookups, 6 providers, seed 261105; faults per request: 10 % 5xx, 5 % 429 (half with Retry-After), 2 % malformed JSON, 1 % timeout

| Provider | Lookups | Skipped | Cached | Reached | ok | not_found | error | Success | Abandoned rl/quota/deadline | Requests | 5xx/429 (RA)/bad JSON/timeout | p95 latency | p95 time to answer |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| virustotal | 100 | 40 | 0 | 100 | 34 | 66 | 0 | 1.000 | 0/0/0 | 117 | 10/6 (5)/0/1 | 0.93 s | 60.6 s |
| abuseipdb | 100 | 45 | 0 | 100 | 35 | 62 | 3 | 0.970 | 0/0/0 | 126 | 17/8 (5)/3/1 | 0.54 s | 59.2 s |
| urlhaus | 100 | 40 | 0 | 100 | 39 | 58 | 3 | 0.970 | 0/0/0 | 121 | 11/7 (1)/3/3 | 0.68 s | 59.5 s |
| malwarebazaar | 100 | 45 | 0 | 100 | 39 | 60 | 1 | 0.990 | 0/0/0 | 123 | 13/10 (7)/1/0 | 0.73 s | 59.9 s |
| otx | 100 | 40 | 0 | 100 | 44 | 54 | 2 | 0.980 | 0/0/0 | 128 | 19/7 (2)/2/2 | 1.76 s | 60.3 s |
| misp | 100 | 35 | 0 | 100 | 36 | 61 | 3 | 0.970 | 0/0/0 | 115 | 10/3 (1)/3/2 | 0.41 s | 0.8 s |
| **all** | 600 | 245 | 0 | 600 | 227 | 361 | 12 | 0.980 | 0/0/0 | 730 | 80/41 (21)/12/9 | 1.08 s | 59.9 s |

- Success = (ok + not_found) / lookups that reached a provider; floor 0.95 per provider. Lowest: 0.970.
- Abandoned: 0 of 600 (rate_limited 0.0 %, quota_exhausted 0.0 %, deadline 0.0 %); 0 of them had reached a provider.
- Ineligible values sent to a provider: 0 (245 skipped values submitted; every request re-checked on the wire).
- Runs: 30 (completed 20, partial 10); slices 111, beat resumes 71; virtual duration 29.5 min.
- Latency is virtual: p95 latency is the worker's own `latency_ms` (the answering attempt); time to answer runs from the first request to the final response (retries, backoff and cooldown waits included).

Pass 2: the same lookups again, right after pass 1 (cache)

| Provider | Lookups | Cached | Cache hit rate | Re-queried | ok + not_found | Requests |
|---|--:|--:|--:|--:|--:|--:|
| virustotal | 100 | 100 | 1.000 | 0 | 0 | 0 |
| abuseipdb | 100 | 97 | 0.970 | 3 | 3 | 3 |
| urlhaus | 100 | 97 | 0.970 | 3 | 3 | 3 |
| malwarebazaar | 100 | 99 | 0.990 | 1 | 1 | 1 |
| otx | 100 | 98 | 0.980 | 2 | 2 | 2 |
| misp | 100 | 97 | 0.970 | 3 | 3 | 3 |
| **all** | 600 | 588 | 0.980 | 12 | 12 | 12 |

- Pass 2 runs: 30 (completed 30); virtual duration 0.1 min.
- Real runtime: 20 s.
