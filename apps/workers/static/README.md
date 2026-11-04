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

## Analysis pipeline (`static_worker/`)

`celery_app` (queue `static`, early ack, one task per child) -> `pipeline.run_job` (started /
finished ingest messages, stable failure codes) -> `analyzer.analyze`: hash-verified download to
`<job>/input/sample` (root-owned, 0444), then every engine as uid 10003 in its own fresh
tool-owned out dir (`<job>/<engine>-out`, created after kill-by-uid; `engines/workspace.py`):

| # | Engine | How | Limits (RT2/RT3/RT4) | Profile |
|---|--------|-----|----------------------|---------|
| 1 | ClamAV | `clamscan --no-summary --infected --allmatch` | `--max-filesize 64M --max-scansize 256M --max-files 10000 --max-recursion 16 --max-scantime` (tool timeout − 30 s: DB load headroom), alerts on limits / encryption; RLIMIT_AS 2 GiB | av, full |
| 2 | YARA | probe `yara` (yara-python, per-scan timeout) | baked + test rule dirs; 1 GiB | av, full |
| 3 | archive pre-check | probe `archive` (own process and out dir, before libmagic): zip structures, real member sizes | inflate ≤ 256 MiB, member ≤ 64 MiB; 1 GiB | av, full |
| 3b | sample facts | probe `facts`: hashes, libmagic, then ssdeep (ppdeep) | ssdeep ≤ 4 MiB (`ssdeep_size_cap`; ppdeep is pure Python, ~0.2 MiB/s); 1 GiB | av, full |
| 4 | PE / ELF | probe `pe` (pefile) / `elf` (pyelftools) | StaticLimits caps; 1 GiB | full |
| 5 | strings | probe `strings`: ASCII + UTF-16LE ≥ 6, dedup, ≤ 512 chars | `max_strings` (¼ kept for FLOSS); 1 GiB | full |
| 6 | capa | `/opt/venv/bin/capa -j`, JSON reduced by probe `capa` | PE/ELF ≤ 16 MiB else `capa_skipped`; JSON ≤ 64 MiB; 2 GiB | full |
| 7 | FLOSS | `floss --only decoded stack tight -j -n 6`, JSON reduced by probe `floss` | PE ≤ 8 MiB else `floss_skipped`; JSON ≤ 32 MiB; 2 GiB | full |

Probes run as `/opt/venv/bin/python -I -s -B -m static_worker.probe <mode> <path>` (a root-owned
`.pth` puts `/srv/workers/static` on the venv path; `-I` ignores the cwd and env) with
`run_tool(cwd=<input dir>)`: their cwd is the root-owned input dir, never a tool-writable one.
Root never parses sample bytes (it only hashes them) nor large tool output: capa's and FLOSS's
JSON documents are parsed by the `capa` / `floss` probe modes as the tool uid and reduced to
JSON lines. Root reads tool output through the kit's bounded readers and accepts only
contract-valid `static.v1` records of the kinds each probe may emit, error codes / truncation
keys from allowlists.

ClamAV is never reported as "clean" when it could not look at everything (RT2). These all add
`av_not_fully_scanned`: limit alerts, encrypted content, a capped output, an error exit / kill /
timeout after hits were printed (the hits are kept), and the archive pre-check
(`probe/archive.py`, its own probe run). ClamAV 1.4 silently trims zip members above
`--max-filesize`, skips zip64 members, extracts members from any local file header it finds
(prefixed zips, PE + zip "SFX", no central directory, odd versions / name lengths) and
inflates the real stream whatever the headers declare. So the pre-check sweeps every complete
local header with a known method, in the file and in each member's real bytes, reads the
central directory with `zipfile`, inflates each stored / deflated member itself and compares
the real size and consumed bytes with the declared ones. It reports `unchecked` for size
mismatches, zip64, local headers outside the central directory that yield data, other
compression methods, broken members, the inflate budget, and 7z / RAR. tar / gzip / bzip2 /
xz need no pre-check: ClamAV raises `Heuristics.Limits.Exceeded.*` for them itself (tested).
When the pre-check result is missing (skipped, timed out, crashed) or was computed over other
bytes than root hashed, and ClamAV produced a verdict, the result also gets
`av_not_fully_scanned` (`truncated.archive_precheck_missing`). A missing DB, or exit code 2
without hits, adds `av_unavailable`.

Known limitation: 7z and RAR are recognised only by their magic at offset 0. A 7z / RAR
archive embedded later in a file (e.g. an SFX installer) is not seen by the pre-check, so a
member ClamAV trims there is not flagged.

Findings (`detections/`, verdict-free templates in `detections/base.py`):
`heuristic:suspicious_api@1` (injection, keylogging, anti-debug, credential access, persistence,
downloader; API *combinations* only), `heuristic:packer@1` (≥ 2 indicators),
`heuristic:pe_anomaly@1` (timestamp, TLS callbacks, high-entropy resources, overlay),
`signature:clamav@1` (`PUA.*` medium, `Heuristics.*` info, else high), `signature:yara@1` (meta
severity, default low; an allowlist keyed on the rule file's sha256 + rule name may raise it,
test-rule entries only when `STATIC_YARA_TEST_RULES` is set), `capability:capa@1` (high-risk
namespaces with an ATT&CK id). Heuristics and capabilities are capped at `medium`. IOCs (URL, domain, IP, email,
registry key, file path) come from the static and FLOSS strings.

Test-only overrides (the test container; prod uses the baked defaults): `STATIC_CLAMAV_DB` (e.g.
`tests/clamav`, EICAR hash + test marker), `STATIC_YARA_TEST_RULES` (`tests/rules/yara`),
`STATIC_CAPA_RULES` (custom capa rules get a per-run cache), `STATIC_CAPA=0`, `STATIC_FLOSS=0`.

## Samples and tests

`samples/` builds the labelled synthetic set at test time (pure-Python PE32/PE32+/ELF64
builders, EICAR assembled from parts, generated zip bombs and RT2 regressions (prefixed / SFX /
nested-prefixed zips with a 70 MiB member, zip64 with a data descriptor, tar.gz; each < 100 KB
on disk), near-miss negatives, mingw-w64 C programs in the dev image; nothing is committed as a
binary and nothing is ever executed). Tests use one work dir per session
(`/work/session-<id>`), so parallel test containers sharing the volume do not wipe each other:

    docker compose --profile test run --rm --no-deps static-worker-test python -m samples.generate /tmp/s

    docker compose --profile test run --rm --no-deps static-worker-test sh -c \
      "ruff check . && ruff format --check . && mypy static_worker tests samples && pytest -q -p no:cacheprovider"

`EVALUATION_OUT=/path.json` writes the detector report, `FUZZ_OUT=/path.json` the fuzz outcomes.

## Phase-1 spike measurements (2026-11-04, prod image, uid 10003, read-only rootfs)

| Engine | Sample | Wall | Peak RSS | VmPeak |
|--------|--------|------|----------|--------|
| clamscan (full DB, 3.6 M sigs) | 40 KB PE | 14–20 s | 1.12 GiB | 1.23 GiB |
| capa (cached rules) | 40 KB PE64 | 19–21 s | 0.87 GiB | 0.96 GiB |
| capa (no cache) | 40 KB PE64 | 42 s | 0.88 GiB | — |
| FLOSS `--only decoded stack tight` | 40 KB PE64 / 231 KB PE32 | 35 s / 42 s | 0.95 / 1.02 GiB | 0.97 / 1.04 GiB |

Image sizes: prod 948 MB, dev 2.61 GB (`docker images`).
