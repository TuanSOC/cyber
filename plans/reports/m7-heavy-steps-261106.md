# M7 phase 11: heavy-step results (2026-11-06)

All numbers come from **synthetic** data on one developer host (Docker engine 29.2.1, 15.3 GiB, 16 CPUs), each step run alone with the WSL page cache dropped first. Not production traffic.

## Restore drill (`pnpm restore:drill`, dev images, bitnami MinIO)

Passed in **146 s**, peak memory **796 MiB**, **0 mismatches**, no warnings (`infra/backup/last-drill.json`).

| Step | Seconds |
|---|---|
| up | 28.8 |
| seed | 5.5 |
| backup (with drain) | 21.9 |
| restore (total) | 68.5 |
| of which `pg_restore` | 1.8 |
| verify `--db` | 3.1 |
| verify `--objects` | 3.1 |
| verify `--rls` | 3.3 |
| post-restore checks | 3.5 |

Verified: 62 tables / 118 rows; 6 evidence object versions (5 re-hashed, 1 tombstoned), 1 signed report version; RLS probe over 20 tables (7 with org B rows). Checks: old session revoked, analyst login, evidence download sha256, report signature valid, report content, purged evidence 410, viewer write forbidden.

## Search performance (`test_search_perf.py`, `SEARCH_PERF=1`, lane 4)

Volume: 2 orgs, 5 000 cases, 10 000 jobs, 200 000 correlation keys, 50 000 findings, 50 000 alerts, 10 000 notes (seeded in 36 s). Passed.

| Type | p95 (s) |
|---|---|
| observable | 0.647 |
| finding | 0.224 |
| alert | 0.130 |
| note | 0.041 |
| case | 0.039 |
| evidence | 0.026 |
| **whole search** | **0.950** |

0 partial responses, no cross-org hit. Under RLS no trigram / FTS index is used (`index_used` false for all 7: the non-LEAKPROOF operators), as recorded in THREAT_MODEL; the floor (p95 < 1 s per type, < 3 s per search) holds at this volume, observables closest to it.

Fix made to run it: the EXPLAIN step lacked the newer `number_like` bind parameter; `lane-test.sh` does not forward `SEARCH_PERF` (run it as `lane-test.sh 4 sh -c "SEARCH_PERF=1 uv run pytest …"`).

## Runtime job metrics (`python scripts/ops_metrics.py --manage-workers`)

See [ops-metric-261106.md](ops-metric-261106.md): 3 rounds, 102 min. pcap 24 jobs, static (`full`) 90 jobs: **0 % failure, 100 % parse success**. pcap run p50 / p95 30.8 / 31.5 s, queue 92.5 / 124.0 s; static run 28.2 / 57.1 s, queue 99.5 / 152.8 s (queueing reflects one worker at a time and the per-user analysis request limit). Fix made: the replay client now refreshes its session after a 401 (the static phase outlived the access token while backing off on 429s).

## Live runs

Not run (needs the user's keys and budget).
