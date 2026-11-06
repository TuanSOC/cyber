---
phase: 5
title: "Offline symbol store fetch and import"
status: pending
priority: P2
effort: "11h"
dependencies: [1]
---

# Phase 5: Offline symbol store, fetch and import (group B, 2d, lane 5)

## Overview
Symbols are the one thing a memory analyzer normally fetches from the internet at analysis time, and in M8 it must not (plan "Symbols: offline only"). This phase builds:
- the **store** the worker reads: the `memory_symbols` volume, mounted read-only, with `manifest.json` and a prebuilt identifier cache;
- the **trusted operator tool** `memory-symbols`, which alone has egress and alone writes the store.

**Owns:**
- `apps/workers/memory/memory_worker/symbols/**`: `store.py` (the phase-1 `SymbolStore` stub), `manifest.py`, `fetch_windows.py`, `import_isf.py` (single ISFs and local zips), `reindex.py`, `isolate.py` (child-process parsing), `__main__.py` (the CLI);
- `tests/unit/test_symbols_{store,manifest,fetch,import,reindex,cli}.py`;
- `tests/integration/test_symbols_tool.py` (a local HTTPS mock server in the test container, never the internet).

## Requirements
- **Store layout and manifest** (`SymbolManifestV1`, frozen in phase 1):
  - `windows/<pdb>/<GUID-AGE>.json.xz`, `linux/<sha256>.json.xz`, `manifest.json`, `.cache/volatility3/identifier.cache`;
  - files 0444 and directories 0555, owned by uid 10005; the worker mounts the volume `:ro`.
- **`SymbolStore(root).lookup(identity) -> SymbolHit | None`** (worker side, read-only):
  - It resolves a `WindowsPdb` by path and a `LinuxBanner` by the manifest's banner index.
  - It verifies the file's sha256 against the manifest before returning (a tampered store gives `symbols_corrupt`).
  - It returns the path and sha256 for the result header.
- **CLI** (`python -I -m memory_worker.symbols <cmd>`; `pnpm memory:symbols -- <cmd>`):
  - **`fetch-windows --pdb --guid --age`:**
    - inputs validated with the frozen `WindowsPdb` model (kernel PDB allow-list, 32 hex, age range);
    - URL `https://msdl.microsoft.com/download/symbols/<pdb>/<GUID><AGE>/<pdb>`, built from validated parts only;
    - `httpx` with TLS verification on and redirects followed manually: at most 3 hops; each hop HTTPS, to a host that equals `msdl.microsoft.com` or ends with one of the suffixes in the constant `SYMBOL_REDIRECT_SUFFIXES` (the Microsoft symbol CDN suffixes documented by Microsoft, recorded with their source in the phase notes); never an IP literal, never userinfo or a non-443 port. No live fetch is ever made to observe the hosts (parent decision), so the constant is changed deliberately when Microsoft changes its CDN, and a refused redirect prints the host so the operator can report it (RT11);
    - ≤ 128 MiB streamed to a temp file;
    - `pdbconv` run as a child process (`isolate.py`) with `RLIMIT_AS` 2 GiB and a timeout, writing into a temp dir;
    - the produced ISF's GUID and age are checked against the request, then it is compressed with xz, placed atomically (`O_EXCL` then rename), recorded in the manifest (`source: msdl`) and reindexed.
    - **Never** Volatility's own downloader (plain HTTP, verification off on SSL error; research §3).
    - **Never run by a test, a gate or the worker** (parent decision): tests use the local HTTPS mock only; the command exists for the operator.
  - **`import --file <path>`** (a file in the operator import dir `/import`, read-only; an operator-built ISF, e.g. dwarf2json ≥ 0.9.0 output for a Linux kernel or a Windows ISF converted elsewhere, or a local `.zip` of ISFs such as a downloaded symbol pack; RT22: the URL-based `import-pack` and its pinned pack list are cut):
    - `.json` / `.json.xz` ≤ 256 MiB decompressed (xz with a memory limit);
    - `.zip`: an optional `--sha256` is checked first; members `^(windows|linux)/[A-Za-z0-9._/-]+\.json(\.xz)?$` with no `..` or absolute paths, ≤ 50 000 members, ≤ 256 MiB each decompressed, a total cap, and no symlinks; `source: zip:<sha256>`;
    - parsing and `jsonschema` validation (against the schema shipped with volatility3 2.28.2) in a child process with `RLIMIT_AS` 2 GiB and a timeout (RT17);
    - identity from metadata (Linux banner, or Windows PDB name / GUID / age);
    - a duplicate identity with a different sha256 is refused unless `--replace` is given, and a replacement is recorded;
    - `source: operator`.
  - **`reindex`:** rebuilds `.cache/volatility3/identifier.cache` with the installed Volatility, offline, in a temp dir, then swaps it in atomically. It runs with the target store mounted at `/symbols` (`memory-symbols` for the main store, `memory-symbols-test` for the test store), because the cache records absolute `file:///symbols/…` locations; it refuses to run when its store root is not `/symbols`, and a test asserts every cached location starts with `file:///symbols/` (RT5).
  - **`verify`:** re-hashes every file against the manifest; exit 1 on any mismatch.
  - **`list`:** identities, sources and import dates (no file contents).
  - No `corpus` command: no third-party memory image or test corpus is ever downloaded (parent decision).
- **Process and network isolation of the tool:**
  - user 10005, `read_only` rootfs with tmpfs `/tmp`, `cap_drop: ALL`, `mem_limit: 2g`;
  - the `symbols_egress` network only (its own bridge: not the shared `egress` of the enrich / analyst workers and mocks; no broker, Postgres, MinIO, backend or analysis networks), so a compromised tool cannot reach platform data or other workers (RT17);
  - no secrets;
  - output only in the mounted symbol volume, always through a temp dir and a verified atomic move;
  - every run logs its command, the URLs fetched and the resulting manifest changes.
- **Offline worker check:** an image that needs a symbol not in the store never causes any fetch. The worker has no code path that calls the tool, and `test_offline.py` (phase 2) covers the Volatility side.
- **Hostile input:** the GUID and banner shown in the UI come from the image. The tool re-validates them, never interpolates them into a shell, and builds the URL from validated parts only. A test feeds every phase-1 hostile `WindowsPdb` string to the CLI.

## Implementation Steps
1. Read Volatility 2.28.2: `symbols/windows/pdbconv.py`, `pdbutil.py`, `automagic/symbol_cache.py`, `schemas/`.
2. Store, manifest, lookup (the worker side first, since phase 2 calls it).
3. `import` (single ISFs, then local zips with the member checks) and `reindex` (mount-path rule); then `fetch-windows` with the HTTPS mock (a self-signed CA trusted only inside the test; redirect chains to allowed and refused suffixes, IP literals, over 3 hops).
4. `verify`, `list`.
5. Lane 5: `scripts/lane-test.sh 5 --service memory-worker-test pytest -q tests/unit/test_symbols_*.py tests/integration/test_symbols_tool.py`; `ruff` / `mypy`.
6. No live fetch and no pack download, by the agent or the parent (parent decision).

## Success Criteria
- [ ] Lookup resolves Windows and Linux identities and refuses a tampered file.
- [ ] `fetch-windows` works against the HTTPS mock, refuses HTTP, hosts outside the suffix list, IP literals, a fourth hop, oversize bodies and a GUID mismatch, and never shells out with input.
- [ ] `import` refuses, for zips, traversal, symlinks, oversize members and a wrong `--sha256`; it validates with `jsonschema` in a child process and records the identity.
- [ ] `reindex` produces a cache whose locations all start with `file:///symbols/` and which the worker uses offline without rescanning.
- [ ] The compose config gives `memory-symbols` the `symbols_egress` network and the symbol volume only (the phase-11 env check asserts it).

## Risk Assessment
- **Microsoft symbol server behaviour** (redirects, CDN hosts, rate limits) can change, and no test observes it (parent decision). The host-suffix list is a recorded constant, updated deliberately; the first real operator fetch may need an update (stated in DEPLOYMENT).
- **Redistribution of PDB-derived ISF** is unverified (research §3). The store is local only, never part of an image or a backup artefact the platform ships. Recorded in DEPLOYMENT.
- **Abyss-W4tcher Linux ISFs** carry no license and their paths change on 2026-11-21. They are not built in; an operator may download one and `import` it at their own judgement (documented).

## Implementation notes (as built, untested in Docker)

Code-only commit `feat(memory): offline symbol store and operator tool (M8 phase 5, untested in Docker)`. Host-only check that passed (Python 3.14, Windows, no Volatility): `pytest --noconftest tests/unit/test_symbols_*.py tests/integration/test_symbols_tool.py` (165 passed; the Volatility-dependent tests skip). `ruff` / `mypy` not run (not available on the host).

- **Modules** (`memory_worker/symbols/`): `store.py` (worker side, read-only), `manifest.py` (layout, `read_manifest`, `StoreWriter`: lock, staging dir inside the store, re-hash of every produced file, `O_EXCL` placeholder then rename, manifest via temp + rename, `changes.jsonl` append-only record, seal to 0444 / 0555), `isolate.py` (child tasks `isf`, `zip`, `pdbconv`, `reindex`: `python -I`, fixed argv, `RLIMIT_AS` 2 GiB, `RLIMIT_FSIZE` 1 GiB, no core, timeout, PEP 578 hook denying sockets / subprocess / exec), `import_isf.py`, `fetch_windows.py`, `reindex.py`, `__main__.py`.
- **Layout details:** Windows `windows/<pdb>/<GUID>-<age decimal>.json.xz` (Volatility's lookup form); Linux `linux/<sha256(banner ASCII)>.json.xz`; every stored ISF is re-compressed by the child (xz preset 6) from the validated bytes. Store root also holds `changes.jsonl` and `.lock` (not ISF extensions, ignored by Volatility).
- **Banner normalization (phase 2 must match):** `memory_worker.symbols.store.normalize_banner(raw: bytes)` cuts at the first NUL and strips surrounding whitespace (the same rule as phase 2's `probe/vol.py::_banner_at`), requires printable ASCII ≤ 512. Probe and import must agree, or Linux lookups miss.
- **Lookup:** identity index over the manifest; an entry whose path is not `isf_relpath(identity)`, a duplicate identity, a missing / symlinked / non-regular file, a sha256 mismatch, or a file at the lookup path that the manifest does not list → `SymbolsCorrupt`.
- **Fetch URL:** `https://msdl.microsoft.com/download/symbols/<pdb>/<GUID><age as upper-case hex>/<pdb>` (symstore convention; equal to decimal for ages < 10). Only `.pdb`, never the CAB `.pd_` form. `trust_env=False` (no proxy / netrc), `Accept-Encoding: identity`, TLS ≥ 1.2 with the system CA store; log lines carry scheme + host + path only (CDN query strings hold signatures).
- **`SYMBOL_REDIRECT_SUFFIXES` (RT11; recorded, not observed):** `.blob.core.windows.net`, `.vsblob.vsassets.io`, `.vsblob.visualstudio.com`. Source: Microsoft Learn, Azure DevOps "Allowed IP addresses and domain URLs" (Artifacts / symbol server storage hosts), which is where `msdl.microsoft.com` symbol downloads are served from. `.blob.core.windows.net` is broad (any Azure storage account); it is reachable only through a redirect issued by `msdl.microsoft.com`, and the converted ISF's PDB name / GUID / age must equal the request. Confirm on the first real operator fetch; a refused hop prints its host.
- **Import caps:** ISF ≤ 256 MiB decompressed; xz decoder memlimit 128 MiB; zip ≤ 50 000 members, ≤ 256 MiB per member, ≤ 4 GiB total decompressed, input file ≤ 8 GiB; zip members that carry no kernel identity (Volatility type tables, non-kernel PDBs) are skipped and reported, any malformed member refuses the whole zip; a member's top dir must match its identity's OS.
- **Reindex:** the child sets `constants.OFFLINE = True`, `REMOTE_ISF_URL = None`, `SYMBOL_BASEPATHS` and `volatility3.symbols.__path__` to the store only, and runs `symbol_cache.SqliteCache(<tmp>/identifier.cache).update()`; work dir under `/tmp` (never inside the store it walks), result checked (every `location` starts with `file:///symbols/`) then copied to staging and renamed into `.cache/volatility3/`. The cache therefore holds no built-in Volatility table locations: the worker's per-plugin `update()` indexes those itself (phase 2 to confirm the cost).

**Remains to run (Docker):** `pytest -q tests/unit/test_symbols_*.py tests/integration/test_symbols_tool.py` in `memory-worker-test` (lane 5) plus `ruff` / `mypy`; in particular verify against the installed 2.28.2: the `pdbconv` CLI flags (`-f`, `-o`) and output form, `SqliteCache(path).update()` and that it neither forks nor opens sockets under the child's audit hook (`test_the_real_indexer_records_only_store_locations`), and the schema location `volatility3/schemas/schema-<format>.json` (`test_schema_dir_discovery_needs_volatility`, `test_the_real_volatility_schema_refuses_a_broken_isf`).
