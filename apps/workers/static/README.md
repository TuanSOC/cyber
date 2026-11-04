# static-worker (untrusted input)

Static malware analyzer. Samples are parsed, never executed; every engine runs as uid 10003.

## Build

From the repo root:

    docker build --build-context jobs=packages/py-jobs --build-context worker_kit=packages/py-worker-kit \
      -t cyberlab/static-worker:dev --target dev apps/workers/static

Stages: `clamav-db` (freshclam, cached; `--build-arg CLAMAV_DB_REFRESH=<date>` refreshes it),
`capa-assets` (capa-rules v10.0.0 + FLIRT sigs, sha256-pinned in `docker/fetch_capa_assets.py`),
`base`, `venv-builder`/`venv-dev`/`venv-prod` (g++ for binary2strings, never shipped),
`dev` (adds mingw-w64 x86-64/i686 for test samples), `prod`.
`docker/finalize_image.py` precomputes the capa rule cache and writes `/etc/cyberlab/versions.json`.

## Runtime paths

| What | Path |
|------|------|
| capa rules / sigs | `/opt/capa/rules`, `/opt/capa/sigs` (`CAPA_RULES`, `CAPA_SIGS`) |
| capa rule cache (read-only) | `/opt/capa/cache` — capa uses `$XDG_CACHE_HOME` itself as the cache dir |
| YARA rules | `/opt/yara/rules` (`YARA_RULES`) |
| ClamAV DB | `/var/lib/clamav` (empty if freshclam failed at build: `clamav_db = "unavailable"`) |
| Tool versions | `/etc/cyberlab/versions.json` |

The kit's `run_tool` scrubs the environment (`PATH` lacks `/opt/venv/bin`, `HOME` = out dir), so
capa/FLOSS must be called by absolute path (`/opt/venv/bin/capa`, `/opt/venv/bin/floss`) and capa
needs `extra_env={"XDG_CACHE_HOME": "/opt/capa/cache"}`; otherwise it rebuilds the cache in the
out dir on every run (~20 s extra).

## Phase-1 spike measurements (2026-11-04, prod image, uid 10003, read-only rootfs)

| Engine | Sample | Wall | Peak RSS | VmPeak |
|--------|--------|------|----------|--------|
| clamscan (full DB, 3.6 M sigs) | 40 KB PE | 14–20 s | 1.12 GiB | 1.23 GiB |
| capa (cached rules) | 40 KB PE64 | 19–21 s | 0.87 GiB | 0.96 GiB |
| capa (no cache) | 40 KB PE64 | 42 s | 0.88 GiB | — |
| FLOSS `--only decoded stack tight` | 40 KB PE64 / 231 KB PE32 | 35 s / 42 s | 0.95 / 1.02 GiB | 0.97 / 1.04 GiB |

Image sizes: prod 948 MB, dev 2.61 GB (`docker images`).
