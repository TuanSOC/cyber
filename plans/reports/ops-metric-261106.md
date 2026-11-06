# Runtime job metrics over a real replay (M7 phase 5)

Generated 2026-11-06 06:09 UTC by `python scripts/ops_metrics.py --manage-workers` in 102.2 min.
Rounds: 3. Phases: pcap, static (one analyzer at a time: yes). Datasets: the M2 synthetic pcap set and the M3 static sample set, generated into a Docker volume and uploaded through the API (`http://api:8000`) by a throwaway org.

## Per analyzer (the replay org, `GET /ops/metrics?window=24h`)

| Analyzer | Profile | Jobs | Succeeded | Failed | Failure rate | Parse success | Queue p50 / p95 | Run p50 / p95 | Failures by class |
|---|---|---|---|---|---|---|---|---|---|
| pcap | - | 24 | 24 | 0 | 0.0% | 100.0% | 92.52 s / 124.04 s | 30.78 s / 31.48 s | - |
| static | full | 90 | 90 | 0 | 0.0% | 100.0% | 99.54 s / 152.78 s | 28.24 s / 57.06 s | - |

## Jobs per round

| Analyzer | Round | Jobs | Failed | Unfinished |
|---|---|---|---|---|
| pcap | 1 | 8 | 0 | 0 |
| pcap | 2 | 8 | 0 | 0 |
| pcap | 3 | 8 | 0 | 0 |
| static | 1 | 30 | 0 | 0 |
| static | 2 | 30 | 0 | 0 |
| static | 3 | 30 | 0 | 0 |

## Failed jobs (file and error code)

- none

## Platform view (`/internal/metrics`, 24h, pcap and static)

Not read: no `METRICS_TOKEN_FILE` is configured on the api (route off).

## Host

- Docker engine 29.2.1: 15.3 GiB RAM, 16 CPUs
- cyberlab-static-worker-1: cyberlab/static-worker:dev (sha256:81b754297b08)
- cyberlab-pcap-worker-test-1: cyberlab/pcap-worker:dev (sha256:8d1e617fd985)
- cyberlab-postgres-1: postgres:17.11-alpine (sha256:266d3c257594)
- cyberlab-api-1: cyberlab/api:dev (sha256:33bfbf752172)
- cyberlab-static-worker-test-1: cyberlab/static-worker:dev (sha256:81b754297b08)
- cyberlab-ingest-beat-1: cyberlab/api:dev (sha256:33bfbf752172)
- cyberlab-ingest-worker-1: cyberlab/api:dev (sha256:33bfbf752172)
- cyberlab-pcap-worker-1: cyberlab/pcap-worker:dev (sha256:8d1e617fd985)
- after the replay: cyberlab-ingest-worker-1 445.1MiB / 15.28GiB
- after the replay: cyberlab-api-1 167MiB / 15.28GiB
- after the replay: cyberlab-ingest-beat-1 97.6MiB / 15.28GiB
- after the replay: cyberlab-postgres-1 393.7MiB / 15.28GiB
- after the replay: cyberlab-minio-1 1.374GiB / 15.28GiB
- after the replay: cyberlab-redis-broker-1 14.28MiB / 15.28GiB
- after the replay: cyberlab-static-worker-1 278.8MiB / 3GiB
- after the replay: cyberlab-redis-1 9.477MiB / 15.28GiB

The gate's own e2e jobs are recorded separately (phase 11).
