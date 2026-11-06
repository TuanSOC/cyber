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
