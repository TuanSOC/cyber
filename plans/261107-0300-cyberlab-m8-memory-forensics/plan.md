---
title: "CyberLab M8 Memory Forensics"
description: >-
  Memory forensics with Volatility 3 (pinned v2.28.2) as a third untrusted analyzer on the
  M2/M3 pattern: an isolated network-less worker that runs an allow-listed set of triage
  plugins, one sandboxed process each, fully offline against a read-only symbol store; a
  versioned `memory.v1` result contract; trusted ingest into new memory tables plus the
  shared findings, IOCs and timeline. Symbols never come from the internet at analysis time:
  a separate trusted `memory-symbols` tool (its own egress network only, no broker, DB or
  MinIO) fetches Windows PDBs over verified HTTPS on operator request and converts them, and
  imports operator-supplied ISFs and local ISF zips; a missing symbol becomes a diagnostic
  result naming what is needed. Memory images are TLP:RED material by default from upload
  (AI and TI excluded until an admin releases them). Deterministic triage heuristics measured
  with precision/recall on a synthetic scenario set, and a time-boxed synthetic Linux image
  (spike run first) for real end-to-end runs; no third-party memory images are downloaded.
  VSL license obligations handled by isolating the adapter. Red-teamed 2026-11-07 (RT1-RT36).
status: pending
priority: P2
effort: 178h
branch: "feat/m8-memory-forensics"
tags:
  - feature
  - memory-forensics
  - volatility
  - analyzer
  - security
blockedBy: [261106-1800-cyberlab-m7-platform-ops]
blocks: []
created: "2026-11-07T03:00:00.000Z"
createdBy: "ck:plan"
source: skill
---

# CyberLab M8 Memory Forensics

## Overview

**Requirements this milestone covers** (`requirement.txt`):
- §1 and §3: "Memory Forensics", "Volatility 3".
- §4: the `memory_forensics` module, with a clear interface and a versioned job schema; "the web API must never execute untrusted files directly".
- §10 and §11: findings, IOCs, timeline, and the `memory_findings` / `forensic_artifacts` tables (mapped: memory findings are `analysis_findings` rows of memory jobs; `forensic_artifacts` become `memory_artifacts`).
- §12: the "Memory Analysis" navigation item (a planned placeholder today).
- §13: secure uploads, file size limits, parser vulnerabilities, evidence integrity, data retention.
- §14: parsing success, analysis latency, detection precision and recall, worker failure rate, for the memory analyzer.
- §16: "Do not use mock results as real analysis findings": every test fixture is labelled, and the replay mode is test-profile only.

**Inputs:**
- ROADMAP "Later" (memory forensics, M8);
- the coverage audit `plans/reports/requirements-coverage-261106.md` (gap 9);
- the research report [`plans/reports/researcher-261107-m8-volatility3.md`](../reports/researcher-261107-m8-volatility3.md);
- the analyzer pattern in `docs/PCAP_ANALYSIS.md` and `docs/MALWARE_ANALYSIS.md`.

**What exists today (scout, 2026-11-07, branch `feat/m7-platform-ops`):**
- **Alembic head:** `0014_m7_platform_ops`. M8 adds **0015** (or head + 1 if an M7 follow-up took 0015; phase 1 confirms).
- **Analyzers:**
  - `analysis/models.py:Analyzer` is the PG enum `analyzer` (`pcap`, `static`).
  - `analysis_jobs.profile` has the checks `profile IN ('full','av')` and `(profile IS NOT NULL) = (analyzer = 'static')` (0006).
  - Per-analyzer parameters live in `analysis/analyzers.py`. Auto-run on upload is decided by `analysis/service.py:auto_choice`.
- **Contracts** (`packages/py-jobs`):
  - `PcapJobV1` / `StaticJobV1` with `PresignedPost`, `JobLimits` / `StaticLimits`;
  - the shared `FindingRecord`, `IocRecord` and `ResultTrailer` (`results.py`);
  - task names and queues in `tasks.py`;
  - `IngestMessageV1` accepts a `failed` outcome with a `result_version_id` (only `succeeded` requires one).
- **Worker kit** (`packages/py-worker-kit`): `sandbox.run_tool` (uid 10003, seccomp without inet sockets, rlimits, kill-by-uid), `transfer.download` (streamed, sha256 and size verified, refused on mismatch), the result writer and bounded parsers.
- **Static worker:** the M3 YARA rules in `apps/workers/static/rules/yara/` with a sha256-keyed severity allow-list; the IOC extractor in `static_worker/detections/iocs.py`.
- **Limits:**
  - `MAX_EVIDENCE_BYTES` is 2 GiB, and Caddy's `CADDY_EVIDENCE_MAX` is 2 GiB + 1 MiB on the upload route only.
  - The default org quota is 20 GiB.
  - Uploads spool to the `upload_tmp` volume.
  - Analyzer scratch is a named `*_work` volume.
- **Share policy (M6):**
  - `evidence_share_policies` (per evidence `ai_excluded`, `ti_excluded`);
  - `investigations/policy.py` resolves it, and TLP:RED implies both flags;
  - the AI context builder skips excluded evidence, and the workers re-check before each provider call.
- **M7:**
  - `job_outcomes.kind` check `IN ('pcap','static','ti','ai','report')`, and the trigger takes `kind` from `analyzer::text`;
  - `retention/select.py:BULK_TABLES`;
  - the correlation indexer reads `iocs`;
  - the dynamic-gate test forbids any `dynamic` analyzer.
- **Lanes:** `scripts/lane-test.sh` accepts lanes 2..8 and the services `api-test` and `report-worker-test`, with `LANE_SLOTS=3`. The lane DB `cyberlab_b8_test` may not exist yet (phase 1 checks). Test services bind-mount their source (e.g. `report-worker-test`), so lanes run worktree code in the phase-1 image.
- **Red-team scout additions (2026-11-07):**
  - **Two-analyzer branches** outside the plan's original file list: `search/service.py:_job_href`, `case_attack/sources.py`, `investigations/timeline.py:_ANALYZER_TITLE`, `ops/{metrics,models,schemas}.py` (`kind: Literal["pcap","static"]`), `reports/{citations,redact}.py`, `ai/context/builder.py:_digest_selections` (non-static → pcap summary), `ai/service_outputs.py`, web `lib/{analysis,correlation,ai}.ts` (`analysisSegment`: non-static → `pcap/…`) (RT1).
  - **Auto-run:** `analysis/service.py:auto_choice` gives every non-empty upload ≤ `STATIC_MAX_BYTES` (64 MiB) an automatic static `av` job, whatever it is (RT3).
  - **Sandbox defaults:** `seccomp.deny_network` denies only AF_INET / AF_INET6 / AF_PACKET unless `unix_sockets_only` / `deny_io_uring` are passed (the M6 renderer passes both); `sandbox.prepare` resets the whole `/work`; the static worker's `Workspace.engine()` makes the per-engine out dirs (RT7, RT26). pcap and static share tool uid 10003, the renderer has 10004 (RT18).
  - **Ingest framing caps:** `ANALYSIS_MAX_RESULT_DECOMPRESSED_BYTES` 1 GiB and `ANALYSIS_MAX_RESULT_LINES` 400 000 for every schema (RT9).
  - **Report snapshot:** `cyberlab.report.v1` has no limitations / notices field; sections carry `total` only, and the renderer validates with `extra="forbid"` (RT10).
  - **Upload:** Caddy `read_body 30m`; `fput_object` uploads multipart (16 MiB parts), so objects above 5 GiB work (RT14).
  - **YARA:** every M3 baseline rule is anchored on `pe.*` or `uint16(0) == MZ`, and the test marker lives only in `tests/rules/yara/` (RT8).
  - **Web:** the shared `components/analysis/iocs-tab.tsx` always renders the Enrich button (RT16).
- **Web:** `lib/nav.ts` lists "Memory Analysis" with `plannedFor`, served by the `[module]` placeholder page.
- **License:** the repository has **no license file**.

Decisions taken by the planner are marked **(decision)**. The red-team pass ran on 2026-11-07; its changes are applied below and in the phase files (table under "Red-team changes").

## Architecture (decided)

    analyst: upload ?kind=memory (≤ MEMORY_MAX_BYTES, 8 GiB default) -> evidence (hashes, custody, quota)
             + memory_sensitivity 'restricted' + share policy AI/TI excluded, in the upload transaction;
             no automatic analysis of any kind (RT3)
             "Run memory analysis" {profile triage|full, os_hint auto|windows|linux}   (never automatic)
      -> API: job row + memory default (idempotent; covers images uploaded without kind=memory) + custody + audit
      -> redis-broker queue `memory` (ACL user `memory`) -> memory.analyze {MemoryJobV1}
    memory-worker (UNTRUSTED, analysis network only, broker URL only)
      -> GET exact evidence version (presigned) to /work/<job>/input/image, sha256 + size verified, root-owned 0444
      -> root: magic check (gzip / bz2 / xz / zstd / zip / 7z -> unsupported_memory_format; RT19)
      -> probe `identify` (uid 10006): layer stacking offline, OS, kernel identity (PDB name/GUID/age
         or Linux banner), symbol lookup in /symbols (read-only volume)
           missing -> diagnostic result {header symbols.required} + failed `symbols_missing`
      -> per allow-listed plugin, in a fixed order: probe `run <plugin>` (uid 10006, seccomp
         AF_UNIX-only + no io_uring, Python audit hook, RLIMIT_AS / FSIZE, timeout, fresh out dir,
         fresh XDG_CACHE_HOME seeded from the read-only identifier cache, HOME empty, Volatility
         OFFLINE, a refusing file handler) -> bounded JSONL rows
      -> root: bounded reads, per-plugin row models -> normalized records -> detections
         -> memory.v1 (gzip NDJSON, header, records, findings, iocs, timeline, trailer)
      -> presigned POST (fixed key, size cap) -> ingest.event finished
    ingest-worker (trusted): token + org from the job index -> validate the whole stream
      -> one transaction: memory_* tables + analysis_findings + iocs + analysis_timeline + custody

    operator: pnpm memory:symbols -- fetch-windows|import|reindex|verify|list   [--store test]
      -> memory-symbols (trusted tool, profile `tools`, its own `symbols_egress` network ONLY: no
         broker, DB, MinIO, backend, analysis or shared egress network) -> writes the
         `memory_symbols` volume + manifest.json; the target store is always mounted at /symbols
      -> mounted read-only into memory-worker(-test)

**Volatility 3** (decision)
- **Pinned `volatility3==2.28.2`** (2026-09-17; there is no 3.x, research §1), installed with explicit dependencies:
  - `pefile`;
  - `capstone` (malfind disassembly);
  - `jsonschema` (without it, ISF schema validation is silently skipped, research §7).
- **Never installed:**
  - `[full]`;
  - `leechcorepyc` (GPLv3, live acquisition only);
  - `pycryptodome` (needed only by hashdump / lsadump / cachedump, which must never run);
  - `pillow`;
  - `pysmb` (Volatility's `smb://` handler);
  - `yara-python` and `yara-x`: M8 runs no YARA (RT8); the YARA plugin modules then fail their import and Volatility skips them.

  A build step asserts the set.
- **Library mode, not the CLI:** the probe drives `volatility3.framework` directly. Library mode gives us:
  - Volatility set to offline, with the same effect as `--offline`: `constants.OFFLINE = True` and `constants.REMOTE_ISF_URL = None` (the 2.28.2 CLI installs no handler of its own; `ResourceAccessor`'s `OfflineHandler` checks the constant, RT7);
  - the symbol paths set to `["/symbols", <volatility3/symbols>, <volatility3/framework/symbols>]`: our store first, then the two read-only built-in directories, which hold the bundled tables plugins need (netscan, PE, bash, generic types). The writable cache fallback entry of `SYMBOL_BASEPATHS` is dropped, so a converted PDB can never be written anywhere (RT2);
  - a Python audit hook (PEP 578) installed after the imports that refuses and counts `socket.*`, `urllib.Request`, `subprocess.Popen`, `os.exec*`, `os.system` and `os.spawn*` events (RT7);
  - a refusing `FileHandlerInterface` passed as `open_method`, so no plugin can write a file whatever its options (RT20);
  - no plugin dirs beyond the built-in ones;
  - a fixed per-plugin configuration;
  - our own TreeGrid visitor, which streams rows with caps and stops at the cap. Volatility's JSON renderers buffer the whole result (research §5).

  The CLI is not used. The `vol` entry point is still on disk.
- **Plugin allow-list** (frozen enum `MemoryPlugin`; research §4: the current names, not the deprecated shims):

  | OS | `triage` | `full` adds |
  |---|---|---|
  | Windows | `windows.info`, `windows.pslist`, `windows.psscan`, `windows.cmdline`, `windows.dlllist`, `windows.netscan`, `windows.malware.malfind`, `windows.svcscan`, `windows.registry.hivelist`, `windows.registry.userassist` | `windows.malware.ldrmodules` |
  | Linux | `linux.pslist`, `linux.psaux`, `linux.bash`, `linux.sockstat` | `linux.lsof`, `linux.malware.malfind`, `linux.malware.check_syscall`, `linux.malware.hidden_modules` |

  Cut by the red team: `windows.handles` (up to 100 000 rows of low triage value; it alone broke the ingest caps, RT9) and every YARA plugin (`windows.vadyarascan`, `yarascan.YaraScan`, `linux.vmayarascan`; RT8).

  - **Never** (tested):
    - credential dumpers (`windows.registry.hashdump`, `lsadump`, `cachedump`);
    - any `--dump` option, `windows.dumpfiles`, `windows.memmap --dump`;
    - `linux.pagecache.*` (tar-slip, PR #1996);
    - `windows.envars` (secrets in environment);
    - registry `printkey`;
    - `windows.handles` and the YARA scanners (cut, RT8 / RT9);
    - the `-o` output dir.

    M8 extracts no files from memory.
  - **Job success:** the identify probe and the process list (`windows.pslist` or `linux.pslist`) succeed. Every other plugin is best effort, and its status (ok, failed, timeout, skipped, unsupported) is reported per plugin in the header, so a partial result is never shown as complete.
- **One process per plugin** (decision): every plugin re-runs the layer stacking (seconds to about a minute; research §6). In exchange, a crash, a hang or a compromised parser in one plugin cannot alter another plugin's output, which is the M3 "fresh out dir per engine" rule. Combining cheap plugins in one process is recorded as an optimisation for later.
- **Real-engine coverage** (RT4): no third-party memory image is downloaded (parent decision: their malware content is unverified). The real Volatility therefore runs in tests only on the synthetic Linux image (phase 4) and on generated non-images (the probe smoke: random and sparse blobs). **Windows plugins are never executed in a test:** they are covered by our row fixtures, the replay engine and a column-drift test that reads each allow-listed plugin's `TreeGrid` columns from the installed 2.28.2 source (phase 2). The docs say "Windows support: replay-tested, not validated on a real image in CI", and DEPLOYMENT gives the operator a manual smoke procedure on their own image (never automatic).
- **Scope:** Windows and Linux, x86 / x64 only. Out of scope:
  - macOS (deprecated upstream in 2.28.2);
  - ARM64 (not merged upstream);
  - hiberfil.sys (no layer upstream);
  - compressed or archived uploads (refused as `unsupported_memory_format`).

  Layers accepted: raw / padded, LiME, AVML, ELF64 core, VMware `.vmem`, and Windows crash dumps (full and bitmap only). A `.vmem` with `.vmss` / `.vmsn` is out of scope, because a job has one evidence file; a `.vmem` alone works when it is a raw image.

**Symbols: offline only** (decision; research §3)
- The worker **never** reaches the internet:
  - it is on the `analysis` network only;
  - tools have no inet sockets (seccomp);
  - Volatility is set offline in code.

  Volatility would otherwise download PDBs from `http://msdl.microsoft.com` over plain HTTP and retry with TLS verification off.
- **The image ships with no symbols** (decision). This keeps it small (the 2019 `windows.zip` is 801 MiB and likely lacks Windows 10 20H1+ and every Windows 11 build). It also avoids redistributing Microsoft-PDB-derived ISF, whose terms are unverified.
- **Symbol store:** the named volume `memory_symbols`, mounted **read-only** into the worker at `/symbols`. Layout:
  - `windows/<pdb>/<GUID-AGE>.json.xz`;
  - `linux/<sha256>.json.xz`;
  - `manifest.json`, `SymbolManifestV1`: per file its sha256, OS, identity (PDB name, GUID, age, or Linux banner), source (`msdl`, `zip:<sha256>`, `operator`), the importing tool version and `imported_at`;
  - `.cache/volatility3/identifier.cache`: prebuilt by `reindex` with the same Volatility version. The cache stores absolute `file:///symbols/…` URLs, so `reindex` always runs with the target store mounted at `/symbols` (`--store test` runs a compose variant that mounts `memory_symbols_test` there); a test asserts every cached location starts with `file:///symbols/` (RT5).
- **Trusted tool `memory-symbols`** (the memory image, uid 10005, compose profile `tools`, `mem_limit: 2g`, its own non-internal network `symbols_egress` and nothing else: never the broker, Postgres, MinIO, backend, analysis or the shared `egress` network of the enrich / analyst workers and the TI / AI mocks (RT17); run by the operator through `pnpm memory:symbols -- …`). Every parse or conversion (`pdbconv`, JSON / `jsonschema`, xz, zip) runs in a child process with `RLIMIT_AS` 2 GiB and a timeout, writes into a temp dir, and the result is verified before an atomic move into the store (RT17). Commands:
  - `fetch-windows --pdb <name> --guid <32 hex> --age <n>` (operator only, **never run by any test, gate or worker**; parent decision):
    - the PDB name must be in the kernel allow-list (`ntkrnlmp.pdb`, `ntoskrnl.pdb`, `ntkrnlpa.pdb`, `ntkrpamp.pdb`);
    - an HTTPS GET of `https://msdl.microsoft.com/download/symbols/…` with TLS verification; redirects followed manually, at most 3 hops, each HTTPS to a host matching the recorded suffix allow-list constant (`msdl.microsoft.com` and the documented Microsoft symbol CDN suffixes), never an IP literal; the list is a constant changed deliberately, because no live fetch exists to observe hosts (RT11);
    - ≤ 128 MiB;
    - the converted ISF's GUID and age must equal the request.
  - `import --file <path>` (a file in the operator-mounted import dir): an operator-built ISF (for example dwarf2json output for a Linux kernel, or a `.json.xz` converted elsewhere), or a **local `.zip` of ISFs** (members checked for traversal, symlinks, type, count and size caps), validated with `jsonschema` against Volatility's schema, with decompression caps; its banner or PDB identity is read from the metadata. The URL-based `import-pack` and its pinned pack list are cut (RT22).
  - `reindex`: rebuilds `.cache/volatility3/identifier.cache` offline (RT5).
  - `verify`: re-hashes every file against the manifest.
  - `list`.
- **Missing symbols → a diagnostic result.**
  - The identify probe reads the kernel identity from the image without symbols: the PDB name, GUID and age by the PDB scan, or the Linux banner. Phase 2 verifies the exact 2.28.2 API.
  - With no matching ISF, the worker uploads a small `memory.v1` stream (header with `symbols.status = missing` and `symbols.required`, and the image facts) and finishes `failed` / `symbols_missing`.
  - The ingest stores only that requirement (`memory_images`). For a Windows requirement the UI shows the exact `pnpm memory:symbols -- fetch-windows …` command, built client-side from the validated fields only; for a Linux requirement it shows the banner as quoted, inert text with a runbook link and **never** a command containing it (the banner is attacker-chosen text, RT12). Members without `org.update` see "ask your operator". "Re-run" is always offered on a `symbols_missing` job, because the API cannot see the store.
  - **The fetch is never automatic** (decision): the GUID comes from attacker-controlled bytes, and the fetch tells a third party which build is investigated. An operator runs it. Strict validation bounds what a hostile GUID can make the tool request.
- **Reproducibility:** the result header records the sha256 of the ISF the run loaded (the probe reports the ISF location Volatility actually used, and root resolves it through the manifest), the Volatility version, the engine and the audit-hook counts.
- **Per-plugin cache:** the identifier cache is copied from `/symbols/.cache` into a fresh tool-owned `XDG_CACHE_HOME` for each plugin and thrown away after it. This addresses the cache-eviction bug #2050 and the truncated-cache bug #2042, and stops one plugin from poisoning the next.

**Resources and limits** (decision)
- **Upload** (`?kind=memory`): `MEMORY_MAX_BYTES` defaults to 8 GiB; the setting is validated ≤ 16 GiB (RT14). `CADDY_EVIDENCE_MAX` becomes max(`MAX_EVIDENCE_BYTES`, `MEMORY_MAX_BYTES`) + 1 MiB on the upload route; the API enforces the per-kind limit on the declared length and while streaming.
  - Caddy's `read_body 30m` stays: an 8 GiB upload needs ≥ 4.6 MB/s sustained, 16 GiB ≥ 9.2 MB/s; DEPLOYMENT states it, with the disk footprint (spool + MinIO while uploading, MinIO + `/work` while analysing; Docker Desktop's virtual disk does not shrink by itself) (RT14).
  - The org quota is unchanged (20 GiB default holds two 8 GiB images; DEPLOYMENT says so).
  - Single-request streaming upload as today. Direct multipart upload to MinIO with a server-side re-hash goes to ROADMAP "Later".
- **No auto-run for memory** (decision): a run costs minutes to an hour and gigabytes of disk, so it is always an explicit action. Raw images have no magic anyway.
- **Worker:**
  - concurrency 1, `--max-tasks-per-child 1`;
  - its own tool uid **10006** (`CYBERLAB_TOOL_UID` / `GID`, the renderer precedent: RLIMIT_NPROC counts every process of a uid on the host) (RT18);
  - seccomp with `unix_sockets_only=True` and `deny_io_uring=True` (RT7);
  - `mem_limit: 3g`, `RLIMIT_AS` per plugin `MEMORY_PLUGIN_RLIMIT_AS` (2.5 GiB), `RLIMIT_FSIZE` 512 MiB per plugin, `oom_score_adj=1000` for tools;
  - `pids_limit 256`, read-only rootfs.
  - `/work` is a named volume (`memory_work`), not tmpfs, because an image can be gigabytes.
  - Before the download, a free-space check (≥ size + 1 GiB, else `insufficient_disk`).
  - The image is read from the local file: random access is required, and Volatility downloads `http(s)` locations in full anyway (research §6).
- **Timeouts:**
  - job `ANALYSIS_MEMORY_TIMEOUT_S` = 5 400 s (≤ the 6 h `JobLimits` bound);
  - plugin `ANALYSIS_MEMORY_PLUGIN_TIMEOUT_S` = 1 200 s;
  - identify = 600 s.

  The reaper adds the M2 grace.
- **Caps:**
  - result ≤ 256 MiB;
  - processes 20 000, connections 50 000, injections 5 000;
  - artifacts 50 000;
  - findings 5 000, IOCs 20 000, timeline 5 000;
  - text fields ≤ 4 KiB (cmdline), hex heads ≤ 64 bytes, disassembly ≤ 1 KiB.

  Every cap hit sets a `truncated` flag. The memory ingest passes its own framing bounds to `check_framing` (`MEMORY_MAX_RESULT_DECOMPRESSED_BYTES` 1 GiB, lines = the sum of the caps + 3), and a unit test proves a stream at every cap fits both the 256 MiB upload cap and these bounds (RT9).
- **Active jobs:** `MEMORY_MAX_ACTIVE_PER_ORG` = 1, `MEMORY_MAX_ACTIVE_TOTAL` = 2. Queue TTL 6 h. The presigned GET expires with the queue TTL plus the job timeout.

**Sensitivity: TLP:RED by default** (decision)
- A memory image can hold passwords, hashes, tokens, keys, mail and documents. **An upload with `kind=memory`** inserts `memory_sensitivity` (`restricted`) and upserts its M6 share policy to `ai_excluded = ti_excluded = true`, never loosening, in the upload transaction, and gets no automatic analysis at all (no static `av` job) (RT3). The first memory job on an evidence item uploaded without `kind=memory` applies the same default (idempotent); jobs that ran on it earlier are covered from then on, and the run dialog says so.
- Through the existing M6 policy machinery:
  - AI runs and job-scope TI on that evidence are `409 policy_blocked`;
  - incident summaries skip it;
  - the workers re-check before every provider call.
- **Release:** `POST …/memory-sensitivity/release` (`org.update`, an acknowledgement and a reason, once, audited), then the analyst clears the flags through the M6 route. While restricted, that route refuses to clear them (`409 memory_sensitivity_restricted`).
- **Reports:** memory-derived rows of restricted evidence go into a report only at TLP:RED; otherwise they are left out and counted in a new additive snapshot field (parent decision, accepted): `ReportSnapshot.omissions: Omissions | None = None` with `memory_restricted: int`, added by phase 1 in `cyberlab_jobs/report.py`. `canonical_json` leaves the key out when it is `None`, so every existing signed snapshot re-serializes to identical bytes (a golden test over the M6 fixtures); the api and report-worker images are rebuilt together (the renderer validates with `extra="forbid"`); the renderers print "N memory items omitted (restricted evidence; TLP:RED required)" (phase 8) (RT10).
- **Secret masking** (RT13): text quoted from command lines and bash history into findings, IOC context and timeline titles (the surfaces that reach the M7 search index, reports, correlation and, after release, AI) passes a deterministic masker (`password=`, `-p<value>`, `/user:<u> <pw>`, `Authorization: Bearer`, `--token` / `--secret` values, AWS access-key ids and secret keys, private-key headers) that keeps the first 2 characters and the length. The raw text stays only in `memory_processes.cmdline` and `memory_artifacts` (job pages, `evidence.read`).
- **Collection minimisation:** no credential plugins, no `envars`, no dumps, no file extraction. Command lines and bash history are kept (core triage value) and are visible to every member with `evidence.read` (org-wide RBAC; a residual in THREAT_MODEL).
- **Correlation** inside the org is allowed: the M7 indexer reads the memory `iocs` rows (keys only, never across orgs).

**License: VSL v1.0** (decision; research §2; not legal advice)
- Redistributing unmodified volatility3 is allowed with its license text: the image keeps the wheel's `LICENSE.txt` and adds `/usr/share/doc/cyberlab-memory/NOTICE`.
- **The adapter is an "Addition"** (the VSL calls "any software designed to execute the software and parse its results, such as a wrapper" an Addition). If it is made available to others, by copies or **over the Internet**, its source must be published under the VSL. M8 therefore:
  - keeps every Volatility-specific line in `apps/workers/memory/` (probe, normalizers, symbol tool), with a `NOTICE.md` stating this;
  - never patches volatility3;
  - keeps the contract, ingest, API and web tool-agnostic.
- **User decision before any external offering:** whether to publish `apps/workers/memory/` under the VSL. The repo has no license today. The planner recommends publishing the adapter directory under the VSL, alongside whatever license the user picks for the rest. M8 builds and runs for the user's own use either way. The question is recorded in Open risks and ROADMAP.

**Detections** (decision; phase 3): deterministic heuristics over normalized records. The methods:
- `heuristic:mem_hidden_process@1`;
- `heuristic:mem_injected_code@1`;
- `heuristic:mem_process_lineage@1`;
- `heuristic:mem_masquerade@1`;
- `heuristic:mem_suspicious_cmdline@1`;
- `heuristic:mem_unlinked_module@1` (full);
- `heuristic:mem_service_path@1`;
- `heuristic:mem_unexpected_network@1`;
- `heuristic:mem_linux_shell_history@1`;
- `heuristic:mem_correlated_indicators@1`.

YARA over memory is cut (RT8): the M3 rules are file rules (`pe.*`, `uint16(0) == MZ`) and mean nothing on scanned memory chunks; memory-specific rules are ROADMAP "Later".

Rules:
- Heuristics cap at `medium`; M8 has no signature method, so nothing reaches `high`.
- No verdict words.
- IOCs: connection remote addresses, and URLs / domains / IPs in command lines and bash history, through the shared extractor lifted into `cyberlab_worker.iocs`.

**Testing and data** (decision; research §8)
1. **Volatility-shaped row fixtures** (our own, hand-written in the 2.28.2 column shapes) unit-test the normalizers and hostile-output handling (phase 2).
2. **Scenario dataset** (phase 3): generated `MemoryView`s, benign baselines and labelled positives. It gives the precision / recall table, with the M2 / M3 caveat (synthetic, designed alongside the detectors).
3. **Synthetic Linux image** (phase 4, **time-boxed at 10 h with a go / no-go, run first**: the spike runs in parallel with phase 1 on host Python, so the result is known before group B starts, RT15):
   - a generated raw image of 16–32 MiB, with LiME and ELF-core wrappers, plus our own minimal ISF;
   - it lets the real Volatility run `linux.pslist` (stretch: `linux.psaux`, `linux.sockstat`) offline in the worker, end to end;
   - it also exercises the symbols-missing path, and its mutations feed fuzz-lite.

   No public project does this (research §8), hence the time box. **No-go fallback:** a test-profile-only replay engine (`MEMORY_ENGINE=replay`) feeds hand-written plugin rows through the real normalizer, detections, ingest and UI. It is refused outside the test profile (env check), and labelled in every result header (`engine: replay`). The real-engine proof then shrinks to the probe smoke (item 4), recorded as such.
4. **Probe smoke** (phase 2, always, independent of the go / no-go; RT4): the real Volatility runs in the worker on a random 16 MiB blob and on a **sparse** 8 GiB file created in the test `/work` tmpfs (holes cost no memory or disk; never uploaded): identify ends `os_undetermined` within its timeout, offline and the audit hook are asserted active, no socket attempt is recorded, and RSS stays below `RLIMIT_AS` although the file is larger than it (proves no layer maps the whole image).
5. **No reference corpus** (parent decision): the `volatility3-test-data` images and every other third-party memory image are never downloaded, by any tool, test or gate (`requirement.txt` §14: no real malware). The test-data symbol zips are not fetched either (they only match those images).
6. **No real malware and no committed memory images** (`requirement.txt` §14).

### Data model (migration **0015**; the M4–M7 conventions: FORCE RLS on every tenant table, composite same-org FKs, S/I grants plus per-column UPDATE, named checks with `octet_length` caps, no DELETE grant to the app role)

| Table / change | Scope / grants | Notes |
|---|---|---|
| `analyzer` enum | existing | `ALTER TYPE analyzer ADD VALUE 'memory'` (autocommit block, like 0006; usable after commit; the downgrade leaves it) |
| `analysis_jobs.profile` checks | existing | replaced: `static` ∈ (`full`, `av`), `memory` ∈ (`triage`, `full`), NULL for `pcap` |
| `analysis_jobs.os_hint` | existing table; write-once by the existing job guard | `auto/windows/linux`, NOT NULL iff analyzer = memory |
| `job_outcomes` kind check | existing | gains `memory` (the trigger already uses `analyzer::text`) |
| `memory_images` | tenant; app S/I | PK `job_id` (composite FK to the job); `os`, `arch`, `layer` (text ≤ 64, e.g. `LimeLayer>Intel32e`), `nt_build`, `kernel_banner` ≤ 512, `pdb_name`, `pdb_guid`, `pdb_age`, `system_time`, `symbols_status` (`resolved/missing`), `isf_sha256`, `volatility_version`, `plugins` jsonb ≤ 16 KiB, `counts` jsonb ≤ 4 KiB |
| `memory_processes` | tenant; app S/I; retention DELETE | `id` uuid PK, `organization_id`, `job_id` (every bulk memory table has these three: `retention/select.py` counts by `t.id`, `organization_id` and `job_id`, and citations reference `id`; RT23), `pid`, `ppid`, `name` ≤ 64, `offset` (`numeric(20,0)`: unsigned 64-bit addresses exceed bigint; the same for every address column below), `create_time`, `exit_time`, `threads`, `handles`, `session_id`, `wow64`, `sources` (bitmask pslist / psscan / pstree), `cmdline` ≤ 4 096, `image_path` ≤ 1 024; unique (`job_id`, `pid`, `offset`); index (`job_id`, `ppid`) |
| `memory_connections` | tenant; app S/I; retention DELETE | `job_id`, `proto`, `local_addr`, `local_port`, `remote_addr`, `remote_port`, `state`, `pid`, `owner`, `created`, `offset` |
| `memory_injections` | tenant; app S/I; retention DELETE | `job_id`, `pid`, `process`, `start`, `end`, `protection`, `tag`, `private`, `commit_charge`, `has_pe`, `head_hex` ≤ 128 chars, `disasm` ≤ 1 024 |
| `memory_artifacts` | tenant; app S/I; retention DELETE | `job_id`, `type` (`module/service/hive/userassist/ldr_unlinked/bash/open_file/syscall_hook/hidden_module`; `handle` and `yara` cut, RT8 / RT9), `pid` NULL, `attributes` jsonb ≤ 4 KiB (scalar values only, checked); index (`job_id`, `type`, `id`) |
| `memory_sensitivity` | tenant; app S/I + UPDATE (`state`, `released_by/at`, `release_reason`) | PK `evidence_id` (composite FK); `state` `restricted/released`; trigger: `restricted → released` once; append-only otherwise |
| retention grants | — | DELETE to `cyberlab_retention` on the four bulk memory tables; never on `memory_images` / `memory_sensitivity` |

Findings, IOCs and the timeline use the shared `analysis_findings`, `iocs` and `analysis_timeline` (that is §11's `memory_findings`). Job-level memory summary: `analysis_jobs.summary` as for static (≤ 32 KiB).

## Red-team changes (2026-11-07)

**Reviewers and sources.** Four hostile reviewers (security, reliability, product, scope / parallelism) checked this plan and the research report against the code:
- worker kit `packages/py-worker-kit/src/cyberlab_worker/{sandbox,seccomp,transfer}.py`; the static worker (`Dockerfile`, `rulefiles.py`, `engines/workspace.py`, `detections/iocs.py`, `rules/yara/`); the report worker layout;
- py-jobs `messages.py`, `limits.py`, `report.py` (snapshot model, `canonical_json`, `Strict`);
- api `core/{config,hashing,storage,upload_slots}.py`, `evidence/uploads.py`, `analysis/{service,analyzers,router}.py`, `investigations/policy.py`, `ioc_collections/`, `retention/select.py`, `correlation/indexer.py`, `search/`, `ops/`, `ai/context/builder.py`, `reports/signing.py`, migrations 0006 and 0014;
- infra and scripts: `docker-compose.yml` (networks, worker anchors, test mounts), `infra/caddy/{Caddyfile,common.caddy}`, `infra/redis-broker/entrypoint.sh`, `scripts/lane-test.sh`; web `lib/{nav,analysis}.ts`, `components/analysis/iocs-tab.tsx`;
- Volatility 3 v2.28.2 source: `cli/__init__.py` (offline, symbol and plugin paths, `vol.json`), `framework/constants`, `framework/layers/resources.py` (`OfflineHandler`, the unverified-TLS retry, transparent xz / bz2 / gzip / zip decompression), `symbols/windows/pdbutil.py` (ISF path from the image's PDB name, converted ISF written to the first writable symbol path), the 2.28.2 plugin tree; and the VSL v1.0 text.

No container was run, nothing was downloaded beyond documentation, and no code was touched.

**Parent decisions encoded:** no Volatility reference corpus or other third-party memory image (synthetic Linux image + test-only replay mode only); no live Microsoft symbol fetch in any test or gate (the operator command exists, mock-tested); the additive report snapshot field for omitted memory items is accepted; VSL publication stays the user's legal decision (adapter isolation + NOTICE, open risk).

**Result:** 36 findings: 4 High, 13 Medium, 19 Low. 27 were accepted and applied, 9 rejected. Seed questions: Q1 → RT4 / RT7 / RT9 / RT20; Q2 → RT2 / RT7 / RT19; Q3 → RT30; Q4 → RT5 / RT11 / RT12; Q5 → RT3 / RT13 / RT31 / RT32; Q6 → RT27; Q7 → RT14 / RT36; Q8 → RT15 / RT33; Q9 → RT21; Q10 → RT8 / RT9 / RT22 / RT28 / RT29 / RT34.

| ID | Finding (failure scenario) | Severity | Disposition |
|---|---|---|---|
| RT1 | **Memory jobs fall into the "else" of two-analyzer code the plan never lists.** `analysisSegment` sends them to `/pcap/{id}`, search links them to `/malware/…`, `ops/schemas.py` `kind: Literal["pcap","static"]` makes the org operations page 500 once a memory job fails, `_digest_selections` builds a pcap summary for them, and citations / case ATT&CK / timeline titles mislabel them. | High | Accepted → phase 1 "analyzer sweep": every two-way branch gets a memory arm (route `memory/{id}`, labels, `ops` kinds and Literals, timeline title, citation tabs, search href, case ATT&CK route), `test_analyzer_exhaustive.py` (api) and a web test assert every analyzer map covers `memory`; the AI digest arm (findings + IOCs only) is phase 8 (plan Frozen interfaces 12; phases 1, 8). |
| RT2 | **"Symbol paths replaced by `/symbols` only" drops Volatility's bundled tables.** `SYMBOL_BASEPATHS` holds `volatility3/symbols` and `volatility3/framework/symbols` (netscan, PE, bash, generic types); without them `netscan` and friends fail on every real image, and no test would notice (no Windows image ever runs). | High | Accepted → paths are `/symbols` + the two read-only built-in dirs, the writable cache fallback dropped (no PDB conversion can be written); the probe asserts the exact list; a test resolves the bundled tables through it (plan Library mode; phase 2). |
| RT3 | **TLP:RED starts too late.** The default is set at the first memory job, but `auto_choice` already gives every upload ≤ 64 MiB an automatic static `av` job, and an analyst can run static `full` (strings → IOCs) and job-scope TI on the image before any memory job: memory contents reach providers unrestricted. | High | Accepted → a `kind=memory` upload applies `apply_memory_default` in the upload transaction and is never auto-analyzed; the first memory job still applies it for other uploads, and the run dialog says earlier jobs are covered from then on (plan Sensitivity, Architecture; phases 6, 8, 9). |
| RT4 | **Without the corpus, real Volatility may never run in CI.** The parent decision removes the only Windows real-engine test; on a phase-4 no-go the probe, the plugin table and library mode (the riskiest code) are exercised only by replay, which bypasses them. | High | Accepted → an always-on probe smoke (random 16 MiB blob and a sparse 8 GiB file in the test tmpfs: `os_undetermined`, offline and audit hook active, RSS below `RLIMIT_AS`); a column-drift test reading each allow-listed plugin's `TreeGrid` columns from the installed source; Windows documented as "replay-tested"; an operator smoke runbook, never automatic (plan Real-engine coverage, Testing; phases 2, 10, 11). |
| RT5 | **The prebuilt identifier cache points at the wrong paths.** It stores absolute `file://` URLs; the test store is reindexed at `/symbols-test` but mounted at `/symbols`, and the cache file lives in `$XDG_CACHE_HOME/volatility3/`. Every plugin would rescan (or fail on) the store. | Medium | Accepted → `reindex` always runs with the target store mounted at `/symbols` (`--store test`), a test asserts every cached URL starts with `file:///symbols/`, root seeds `$XDG_CACHE_HOME/volatility3/identifier.cache` (plan Symbols; phases 1, 2, 5). |
| RT6 | **Concurrent lanes destroy each other.** Phases 2–5 all run `memory-worker-test`; `sandbox.reset` empties the whole `/work`, which the plan makes the shared `memory_work_test` volume, and phases 4 / 5 would write the shared `memory_symbols_test` store. The test mounts must also cover `dataset/` and `samples/`. | Medium | Accepted → `memory-worker-test` gets a per-container tmpfs `/work` (512 MiB; sparse files allowed); unit and engine tests build their own symbol store in a temp dir (`MEMORY_SYMBOLS_DIR`); the `memory_symbols_test` volume is used only by phase 11's pipeline run; bind mounts for `memory_worker/`, `tests/`, `samples/`, `dataset/` (plan Frozen interfaces 8; phases 1, 2, 4, 5). |
| RT7 | **Network denial is weaker and less provable than claimed.** The kit's default filter leaves AF_NETLINK / AF_VSOCK / … and io_uring open; `--offline` sets only `constants.OFFLINE` (no handler is installed); phase 11's "audit of connect attempts" has no mechanism behind it. | Medium | Accepted → seccomp `unix_sockets_only` + `deny_io_uring`; `OFFLINE` and `REMOTE_ISF_URL` set in code; a PEP 578 audit hook refuses and counts socket, urllib, subprocess and exec events into `status.json`, and phase 11 asserts zero (plan Library mode, Worker; phases 2, 11). |
| RT8 | **YARA over memory with the M3 rules is noise or nothing.** Every baseline rule is anchored on `pe.*` / `uint16(0) == MZ` of the scanned buffer, the test marker is not in the image rules, and concatenating files breaks the sha256-keyed allow-list. | Medium | Accepted → all YARA plugins, `signature:yara@1`, the `yara` artifact type, `yara-python` and the rules build context are cut; memory-specific rules go to ROADMAP "Later" (plan Volatility, Detections; phases 1, 2, 3, 7, 9, 10). |
| RT9 | **A maximal result is refused by its own ingest.** 200 000 artifacts × 4 KiB attributes exceed `ANALYSIS_MAX_RESULT_DECOMPRESSED_BYTES` (1 GiB), and the lines approach the shared 400 000 cap; `windows.handles` alone is 100 000 rows of little triage value. | Medium | Accepted → `windows.handles` cut; artifacts 50 000, timeline 5 000; the memory ingest passes its own framing bounds; a test proves a stream at every cap fits (plan Caps; phases 1, 2, 6). |
| RT10 | **The omitted-count field does not exist, and adding it naively breaks signatures.** `cyberlab.report.v1` has no limitations field; a new defaulted key would change the canonical bytes of re-serialized signed snapshots, and the renderer (`extra="forbid"`) refuses it until rebuilt. | Medium | Accepted (parent decision) → `ReportSnapshot.omissions: Omissions \| None = None`, left out of `canonical_json` when `None`, a golden test over the M6 fixtures, added by phase 1; api and report-worker rebuilt together; phase 8 fills it and prints the line in the Markdown / HTML renderers (plan Sensitivity; phases 1, 8). |
| RT11 | **The redirect allow-list was to be "observed" by a live fetch that is now forbidden.** Microsoft's symbol server redirects to rotating CDN host names. | Medium | Accepted → HTTPS only, ≤ 3 hops, a recorded host-suffix allow-list constant, no IP literals, tested against the local HTTPS mock only; operator-run only (plan Symbols; phase 5). |
| RT12 | **The symbols-missing UI can hand an operator a poisoned command.** The Linux banner is up to 512 attacker-chosen printable characters; pasting a command that embeds it into a shell is command injection on the operator's host. | Medium | Accepted → only Windows gets a command, built client-side from the validated PDB name, GUID and age; the banner is shown as inert quoted text with a runbook link; non-admins see "ask your operator"; "Re-run" always offered (plan Symbols; phase 9). |
| RT13 | **Secrets in command lines and bash history spread beyond the job page.** Findings quote them, and finding titles / descriptions are in the M7 org-wide search index, reports (at TLP:RED) and AI context after release. | Medium | Accepted → a deterministic secret masker for every text quoted into findings, IOC context and timeline titles; raw text only in `memory_processes` / `memory_artifacts` (plan Sensitivity; phase 3). |
| RT14 | **The 32 GiB ceiling cannot be uploaded.** Caddy's `read_body 30m` needs ≥ 18 MB/s for 32 GiB; each image also holds two copies on Docker Desktop's growing virtual disk. | Medium | Accepted → `MEMORY_MAX_BYTES` ≤ 16 GiB (default 8 GiB), `read_body` unchanged; DEPLOYMENT states throughput and disk footprint (plan Resources; phases 1, 6, 10). |
| RT15 | **The go / no-go comes too late to steer anything.** Phase 4 runs in parallel with the phases it should inform (phase 2's engine tests, phase 11's e2e). | Medium | Accepted → the 10 h spike runs first, in parallel with phase 1, on host Python in its own worktree (owns only `samples/memgen/**` and its notes, no containers); the decision is recorded before group B starts (plan Testing, Phases, Parallel execution; phase 4). |
| RT16 | **Phase 9 cannot hide "Enrich".** It lives in the shared `iocs-tab.tsx`; and after release the flags are still set, so the e2e's "Enrich appears" step needs the share-policy PUT too. | Low | Accepted → phase 1 adds an `enrichDisabledReason` prop to `IocsTab`; the e2e releases, clears the flags, then sees Enrich (plan Frozen interfaces 11; phases 1, 9, 11). |
| RT17 | **The symbol tool shares the egress bridge and parses as the store owner.** It would sit next to the enrich / analyst workers and the TI / AI mocks; `pdbconv`, zip and 256 MiB JSON parsing run unbounded as uid 10005. | Low | Accepted → own `symbols_egress` network, `mem_limit 2g`, parsing in a child with `RLIMIT_AS` and a timeout, temp dir then verified atomic move (plan Symbols; phases 1, 5). |
| RT18 | **Tool uid 10003 is shared with pcap and static.** RLIMIT_NPROC counts per host uid (the M6 renderer moved to 10004 for this). | Low | Accepted → memory tool uid 10006 via `CYBERLAB_TOOL_UID` (plan Worker; phases 1, 2). |
| RT19 | **Volatility decompresses locations transparently** (xz, bz2, gzip, zip): a small bomb becomes a CPU / disk DoS. | Low | Accepted → root refuses compressed and archive magic (bz2 added) before any probe runs (plan Architecture; phase 2). |
| RT20 | **Output safety relies on per-plugin `dump=False` flags.** | Low | Accepted → a refusing `FileHandlerInterface` as `open_method`; `RLIMIT_FSIZE` 512 MiB per plugin (plan Library mode; phase 2). |
| RT21 | **Two detectors fire on clean Windows 10+.** Defender runs from `\ProgramData\Microsoft\Windows Defender\Platform\`; `wininit` / `csrss` parents (session `smss` instances) have normally exited. | Low | Accepted → a constant exclusion list for the service-path rule; a missing parent never fires lineage; finding titles say "private executable region" rather than "injected code" (phase 3). |
| RT22 | **`import-pack` URLs, the pinned test-data packs and `corpus fetch` serve only the dropped corpus.** | Low | Accepted → cut; `import` accepts a local ISF zip with the same member checks; `memory_corpus` volume removed (plan Symbols, Testing; phases 1, 2, 5, 10, 11). |
| RT23 | **Retention and citations need `id`, `organization_id` and `job_id`** on every bulk table (`retention/select.py` counts by `t.id`). | Low | Accepted → stated in the data model (phase 1). |
| RT24 | **`idor_cases_memory.py` (phase 7) would hold phase-8 routes** that answer 501 in lane 7. | Low | Accepted → `idor_cases_memory_sensitivity.py`, owned by phase 8 (plan Frozen interfaces 10; phases 1, 7, 8). |
| RT25 | **`symbols_missing` as `infra` inflates the §14 worker failure rate.** | Low | Accepted → class `input` (plan Frozen interfaces 6; phase 1). |
| RT26 | **`sandbox.prepare` resets `/work`**, so calling it per plugin deletes the image; the kit's layout is `input/`, not `in/`. | Low | Accepted → per-plugin out dirs through the static `Workspace.engine()` pattern; image at `input/image` (phase 2). |
| RT27 | **VSL "Additions" also covers content and training materials that contain any portion of the software.** Docs pasting Volatility source would become VSL material. | Low | Accepted → docs link to upstream, never paste its source; fixtures are our own; NOTICE says so; publication stays an open user decision (plan License, Open risks; phase 10). |
| RT28 | Cut Windows support (no real-engine test). | Medium | Rejected → Windows images are the main analyst need; RT2 / RT4 bound the risk and the docs state "replay-tested". |
| RT29 | Cut `fetch-windows` / PDB conversion (operators convert elsewhere). | Low | Rejected → the one-command symbols-missing workflow is the operator path; never automatic, mock-tested only (RT11). |
| RT30 | Combine cheap plugins in one process to save repeated layer stacking. | Low | Rejected for M8 → isolation is the point; recorded as "Later" once timings exist. |
| RT31 | Hide command lines and bash history from non-admins. | Medium | Rejected → needs per-field RBAC beyond the M1 org model; RT13 masks secrets on the shared surfaces; residual in THREAT_MODEL. |
| RT32 | Exclude memory IOCs from in-org correlation. | Low | Rejected → keys only, never across orgs, and the main cross-case pivot. |
| RT33 | Drop the synthetic Linux image (replay only). | Low | Rejected → with the corpus gone it is the only kernel-structure proof; time-boxed and run first (RT15). |
| RT34 | Cut the `full` profile. | Low | Rejected → after RT8 / RT9 it is five cheap plugins. |
| RT35 | noexec tmpfs `/work` in prod (the static RT4 rule). | Low | Rejected → images are GiBs; the tool can already run arbitrary Python, so exec adds nothing past seccomp and the uid. |
| RT36 | Resumable / direct multipart upload in M8. | Low | Rejected → ROADMAP "Later" as planned; RT14 bounds the single request. |

Seed questions given to the reviewers (kept for traceability):

1. Can a hostile image make the identify probe or a plugin escape its limits: RSS above `RLIMIT_AS` through mmap, a hang beyond the timeout, gigabytes of rows before the visitor's cap?
2. Does the library-mode offline switch really cover every network path in 2.28.2 (urllib handlers, the remote ISF cache, the PDB downloader, `jar:` / `s3:` locations), with seccomp as the second layer?
3. Is the per-plugin process model worth its cost (repeated layer stacking on a 16 GiB image), or should cheap plugins share a process?
4. Can a hostile PDB GUID or banner, relayed through the UI to an operator, make `memory-symbols` fetch an arbitrary URL, write outside the store or overwrite another ISF?
5. Is "TLP:RED by default, admin release" enough for memory contents? Should command lines and bash history be hidden from non-admins? Is correlation of memory IOCs acceptable?
6. Are the VSL obligations correctly scoped (adapter only), and is anything else an "Addition": the contract, the ingest, the UI, the docs?
7. Do 8 GiB uploads through Caddy and uvicorn, the `upload_tmp` spool and the 20 GiB quota hold on Docker Desktop's disk? Is single-request upload acceptable for M8?
8. Is the synthetic Linux image worth 10–18 h, against the replay mode plus the reference corpus?
9. Are any detectors noise on real systems (malfind on JIT hosts, lineage with exited parents)? Should they be `low` or `info`?
10. Scope: is anything YAGNI for a learning-grade single-node platform, e.g. the `full` profile, Linux support, the reference corpus or the YARA scans?

## Phases

| Phase | Name | Group | Depends on | Status |
|-------|------|-------|------------|--------|
| 1 | [Foundation contracts migration and memory worker skeleton](./phase-01-foundation-contracts-migration-and-memory-worker-skeleton.md) | A | — | Pending |
| 2 | [Volatility engine runner and memory v1 normalization](./phase-02-volatility-engine-runner-and-memory-v1-normalization.md) | B (2a, lane 2, `--heavy` for engine runs) | 1 | Pending |
| 3 | [Memory detections and plugin output scenario dataset](./phase-03-memory-detections-and-plugin-output-scenario-dataset.md) | B (2b, lane 3) | 1 | Pending |
| 4 | [Synthetic memory image generator and engine smoke](./phase-04-synthetic-memory-image-generator-and-engine-smoke.md) | spike: A′ (parallel with phase 1, host Python, no containers); rest: B (2c, lane 4, `--heavy`) | spike: —; rest: 1 | Pending |
| 5 | [Offline symbol store fetch and import](./phase-05-offline-symbol-store-fetch-and-import.md) | B (2d, lane 5; one live fetch is a heavy step) | 1 | Pending |
| 6 | [Memory dispatch and trusted ingest](./phase-06-memory-dispatch-and-trusted-ingest.md) | B (2e, lane 6) | 1 | Pending |
| 7 | [Memory read API](./phase-07-memory-read-api.md) | B (2f, lane 7) | 1 | Pending |
| 8 | [Sensitivity policy reports AI TI and retention integration](./phase-08-sensitivity-policy-reports-ai-ti-and-retention-integration.md) | B (2g, lane 8) | 1 | Pending |
| 9 | [Memory analysis frontend](./phase-09-memory-analysis-frontend.md) | B (2h, web only) | 1 (frozen contracts) | Pending |
| 10 | [Docs threat model and license notices](./phase-10-docs-threat-model-and-license-notices.md) | C | B merged | Pending |
| 11 | [Hardening e2e fuzz metric and gate](./phase-11-hardening-e2e-fuzz-metric-and-gate.md) | D | all | Pending |

Effort (after the red team): 27 + 27 + 15 + 18 + 11 + 19 + 10 + 17 + 13 + 8 + 13 = **178 h** (was 172 h: phase 1 +3 analyzer sweep and report field; phase 2 +1 probe smoke, column drift and audit hook, net of the corpus and YARA cuts; phase 3 +1 masking, net of YARA; phase 5 −3 no `import-pack`, corpus or live fetch; phase 6 +1 upload-time default and memory framing; phase 8 +3 omissions rendering and the AI arm; phase 9 +1 symbols-missing UX; phase 11 −1 no corpus metrics). Critical path: 1 → max(B) (phase 2, 27 h) → 10 → 11, about 27 + 27 + 8 + 13 = **75 h** of wall time with eight group-B agents; the phase-4 spike (10 h) runs beside phase 1 and is off the path. At most three lane slots at once, and a `--heavy` lane takes two.

## Dependencies and parallelism

**Cross-plan:** blocked by `261106-1800-cyberlab-m7-platform-ops`. Its gate (`pnpm verify:prod` with the restore drill) must be green and merged first. Phase 1 then:
- confirms the alembic head (`0014`, or the M7 follow-up);
- confirms that the M7 files it edits are final: `analysis/{models,analyzers}.py`, `workers/{celery_app,tasks,ingest}.py`, `ops/error_classes.py`, `retention/select.py`, compose, `infra/redis-broker/entrypoint.sh`, `scripts/lane-test.sh`, `lib/{nav,audit-actions,http-errors}.ts`;
- creates `feat/m8-memory-forensics` from the M7 merge.

The MinIO image decision of M7 (user) does not block M8.

**Group A: phase 1, one agent; frozen when committed.** Only the parent changes frozen files afterwards. A change request goes to the parent, which decides and broadcasts it.

**Frozen interfaces** (phase 1 notes record the exact signatures):
1. **Contract `packages/py-jobs/src/cyberlab_jobs/memory.py`**, exported from `__init__.py`:
   - `MEMORY_SCHEMA = "memory.v1"`;
   - `MemoryProfile` (`triage`, `full`) and `OsHint` (`auto`, `windows`, `linux`);
   - `MemoryPlugin` (the allow-list above) and `PLUGINS_BY_PROFILE`;
   - `MemoryLimits` (the caps above, `tool_timeout_s < timeout_s`);
   - `MemoryJobV1` {`job_id`, `organization_id`, `evidence_id`, `expected_sha256`, `size_bytes`, `evidence_url`, `result_post`, `ingest_token`, `profile`, `os_hint`, `limits`}.
   - **The result lines:**
     - `MemoryResultHeader` {`job_id`, `profile`, `os`, `engine` (`volatility3` | `replay`), `tool_versions`, `symbols` {`status`, `isf_sha256?`, `required?`: `WindowsPdb{name, guid, age}` | `LinuxBanner{banner}`}, `plugins[]` {`plugin`, `status`, `rows`, `truncated`, `duration_ms`, `error_code?`}, `engine_errors`, `truncated`};
     - `MemoryImageRecord` {`size_bytes`, `sha256`, `layer`, `arch`, `nt_build?`, `kernel_banner?`, `system_time?`};
     - `MemoryProcessRecord`, `MemoryConnectionRecord`, `MemoryInjectionRecord`, `MemoryArtifactRecord` (the table columns);
     - the shared `FindingRecord`, `IocRecord` and timeline record, and `ResultTrailer`.
   - **`SymbolManifestV1`** (the store manifest shared by the worker and the tool; sources `msdl`, `zip:<sha256>`, `operator`).
   - **Framing:** header first, trailer last, the M3 value bounds.
   - **Diagnostic stream** (`symbols_missing`): header + at most an image line + trailer.

   Task `MEMORY_ANALYZE = "memory.analyze"`, `Queues.memory`.

   **Report snapshot field** (parent decision, RT10): `cyberlab_jobs/report.py` gains `Omissions(Strict){memory_restricted: int ≥ 0}` and `ReportSnapshot.omissions: Omissions | None = None`; `canonical_json` omits the key when `None`; `test_report_canonical_golden.py` proves every M6 snapshot fixture keeps its bytes and sha256.
2. **Fixtures `tests/fixtures/memory/`** (in py-jobs, shared by the API and the worker): `windows_triage.ndjson`, `linux_triage.ndjson`, `symbols_missing.ndjson` and `hostile/*.ndjson`, round-tripped by `test_memory_contract.py`.
3. **Migration 0015** and the models in `app/modules/memory_analysis/models.py`; `Analyzer.MEMORY`. Later schema needs go into **0016**, assigned by the parent.
4. **Schemas and 501 stubs** for every new route, then one `pnpm gen:contracts` run:
   - `memory_analysis/schemas.py`;
   - the analysis request body gains `os_hint` and the memory profiles;
   - `EvidenceOut.memory_sensitivity`;
   - the error codes `memory_image_too_large` (413), `memory_image_empty`, `memory_sensitivity_restricted`, `memory_sensitivity_released`, `acknowledgement_required`, `insufficient_storage` (507). (`memory_requires_tlp_red` is dropped: the accepted `omissions` field replaces the refusal, RT10.)

   Routes (under `/api/v1/orgs/{org_id}`):

   | Method and path | Permission | Phase |
   |---|---|---|
   | `GET /analyses/{job}/memory` | `evidence.read` | 7 |
   | `GET /analyses/{job}/memory/processes`, `…/processes/{pid}` | `evidence.read` | 7 |
   | `GET /analyses/{job}/memory/connections`, `…/injections`, `…/artifacts` | `evidence.read` | 7 |
   | `GET /evidence/{id}/memory-sensitivity` | `evidence.read` | 8 |
   | `POST /evidence/{id}/memory-sensitivity/release` | `org.update` | 8 |
   | existing `POST /evidence/{id}/analyses` (`analyzer: memory`) | `evidence.write` | 6 |
   | existing `POST /investigations/{inv}/evidence?kind=memory` | `evidence.write` | 6 |
5. **Cross-phase entry points** (stubs; ownership moves to the named phase, which never changes the signature):
   - `memory_analysis/sensitivity.py: async apply_memory_default(session, org_id, evidence_id, actor_id) -> bool` (phase 8; called by phase 6);
   - `memory_analysis/dispatch.py: build_memory_message(item, settings) -> MemoryJobV1` (phase 6);
   - `memory_analysis/ingest.py: async ingest_memory(job, msg, path) -> None` and `async ingest_memory_diagnostic(job, msg, path) -> None` (phase 6), called from `workers/ingest.py` by schema version;
   - worker `memory_worker/detections/__init__.py: run(view: MemoryView, limits: MemoryLimits) -> DetectionOutput` (phase 3; called by phase 2);
   - worker `memory_worker/symbols/store.py: SymbolStore(root).lookup(identity) -> SymbolHit | None` and `.manifest()` (phase 5; called by phase 2);
   - `cyberlab_worker/iocs.py` (**implemented** in phase 1: the static extractor lifted verbatim, with a re-export shim in `static_worker/detections/iocs.py`).
6. **`ops/error_classes.py`** gains every memory code (**implemented** in phase 1). Examples:
   - `symbols_missing` → input (an operator gap, not a worker failure; RT25);
   - `memory_parse_failed`, `os_undetermined` → parse;
   - `unsupported_memory_format`, `memory_image_too_large` → input;
   - `insufficient_disk` → infra;
   - `plugin_timeout` → infra.
7. **Settings** (`core/config.py`): `MEMORY_MAX_BYTES` (≤ 16 GiB, RT14), `MEMORY_MAX_RESULT_BYTES`, `MEMORY_MAX_RESULT_DECOMPRESSED_BYTES` (RT9), `ANALYSIS_MEMORY_TIMEOUT_S`, `ANALYSIS_MEMORY_PLUGIN_TIMEOUT_S`, `MEMORY_MAX_ACTIVE_PER_ORG`, `MEMORY_MAX_ACTIVE_TOTAL`, the per-kind caps, `MEMORY_TREE_MAX_NODES`. Worker settings: `MEMORY_PLUGIN_RLIMIT_AS`, `MEMORY_SYMBOLS_DIR`, `MEMORY_ENGINE` (`volatility3`; `replay` is refused unless `TEST_PROFILE=1`), `CYBERLAB_TOOL_UID` / `GID` = 10006 in the image.
8. **Services** (compose; dev, test and prod):
   - `memory-worker`: the analysis network, the broker URL only, `memory_work` and `memory_symbols:ro` volumes, the M3 isolation keys;
   - `memory-worker-test`: the same, but `/work` is a per-container tmpfs (512 MiB) and `memory_symbols_test:ro` (used only by phase 11's pipeline run; tests build temp stores), with bind mounts of `memory_worker/`, `tests/`, `samples/` and `dataset/` (RT6);
   - `memory-symbols` (profile `tools`, network `symbols_egress` only, `mem_limit 2g`, `memory_symbols` rw at `/symbols`; a `--store test` variant mounts `memory_symbols_test` at `/symbols` instead; RT5, RT17);
   - the network `symbols_egress` (non-internal bridge, used by nothing else);
   - the broker ACL user `memory` (the analyzer pattern);
   - `CADDY_EVIDENCE_MAX` raised;
   - `scripts/lane-test.sh` accepts `--service memory-worker-test` and `--heavy` (takes two slots); `cyberlab_b8_test` created if missing;
   - `package.json`: `memory:symbols` (the compose run wrapper, implemented) and `memory:metrics` (stub, exit 2).
9. **Worker skeleton** `apps/workers/memory/`:
   - `Dockerfile`: pinned deps and the forbidden-deps assertion (no YARA engine, RT8); tool uid 10006; site-packages root-owned; `HOME=/nonexistent`; the wheel's `LICENSE.txt` kept; `versions.json`;
   - `pyproject.toml`, `uv.lock`;
   - `memory_worker/{celery_app,config}.py` (implemented);
   - `analyzer.py` (stub: fails `not_implemented`);
   - empty `probe/`, `normalize/`, `engines/`, `detections/`, `symbols/`, `samples/`, `dataset/` packages;
   - `tests/conftest.py`;
   - the py-worker-kit isolation tests wired into the image.
10. **Test helpers:** `tests/memory_helpers.py` (`seed_memory_job()` from the fixture, `restricted_memory_evidence()`); `tests/security/idor_cases_memory.py` (the phase-7 routes) and `idor_cases_memory_sensitivity.py` (the phase-8 routes), each with `PENDING_ROUTES` (RT24); `test_rls_coverage.py`, `test_append_only.py` and the dynamic-gate test updated, then frozen.
11. **Web shared:**
    - `lib/nav.ts` (Memory Analysis live), `lib/audit-actions.ts` (`memory.*`), `lib/http-errors.ts` (the codes above);
    - the analyzer badge value `memory`;
    - the empty slots mounted once: `components/memory/run-memory-analysis.tsx` (in `evidence-analyses-card.tsx`), `components/memory/memory-upload-option.tsx` (in `evidence-uploader.tsx`), `components/memory/memory-sensitivity-badge.tsx` (in the evidence page);
    - `components/analysis/iocs-tab.tsx` gains an optional `enrichDisabledReason` prop (RT16).
12. **Analyzer sweep** (RT1, implemented): a memory arm in every two-analyzer branch — `search/service.py:_job_href`, `case_attack/sources.py`, `investigations/timeline.py:_ANALYZER_TITLE`, `ops/{metrics,models,schemas}.py` (kinds and Literals), `reports/{citations,redact}.py`, `ai/service_outputs.py`, `analysis/{schemas,service}.py` (profile rules, too-large error map), web `lib/{analysis,correlation,ai}.ts` (route `memory/{id}`, labels "Memory (triage)" / "Memory (full)"); `tests/unit/test_analyzer_exhaustive.py` and `lib/analysis.test.ts` fail when a map misses an `Analyzer` member. The memory arm of `ai/context/builder.py:_digest_selections` is a stub raising `NotImplementedError` until phase 8.

**Group B: phases 2–9, in parallel** (one subagent each, own worktree from the phase-1 commit, file-disjoint). Each phase's tests pass in isolation against the phase-1 stubs, fixtures and frozen schemas. Cross-phase behaviour is tested after the merge (phase 11). Nobody runs `pnpm verify` or the full suite in a lane.

| Phase | Owns (creates or edits; nobody else touches these in group B) |
|---|---|
| 2 (2a) | `apps/workers/memory/memory_worker/{analyzer,pipeline}.py`, `probe/**`, `normalize/**`, `engines/**` (the Volatility runner and the test-only replay engine), `tests/fixtures/vol_rows/**`, `tests/unit/test_{runner,probe,normalize_*,hostile_output,offline,plugin_allowlist,plugin_columns,symbol_paths,audit_hook}.py`, `tests/engine/test_probe_smoke.py` |
| 3 (2b) | `memory_worker/detections/**` (including the secret masker `detections/mask.py`), `apps/workers/memory/dataset/**`, `tests/unit/test_detections_*.py`, `test_mask.py`, `test_dataset_quality.py`, `test_finding_wording.py` |
| 4 (spike A′, then 2c) | `apps/workers/memory/samples/memgen/**`, `samples/isf/**` (our generated minimal ISF), `tests/engine/test_synthetic_linux.py`, `tests/unit/test_memgen.py`, the spike notes in the phase file |
| 5 (2d) | `memory_worker/symbols/**` (store, manifest, fetch, import, reindex), `tests/unit/test_symbols_*.py`, `tests/integration/test_symbols_tool.py` (local HTTPS mock) |
| 6 (2e) | see phase 6: `memory_analysis/{dispatch,ingest,stream}.py`, the memory branches of `analysis/{service,dispatch,analyzers}.py`, `workers/{ingest,reaper}.py`, `evidence/uploads.py` (with the upload-time memory default), `core/filetypes.py`, its tests |
| 7 (2f) | `memory_analysis/{router,repository,service}.py`, `tests/security/idor_cases_memory.py`, its tests |
| 8 (2g) | `memory_analysis/{sensitivity,router_sensitivity}.py`, the guards in `evidence/share_policy.py` and `reports/snapshot_sections.py`, the omissions line in `apps/workers/report/report_worker/render_{md,html}.py`, the memory arm of `ai/context/builder.py`, `retention/select.py` (`BULK_TABLES`), `tests/security/idor_cases_memory_sensitivity.py`, its tests |
| 9 (2h) | `apps/web/lib/{memory,memory-sensitivity}.ts` (+ tests), `lib/use-memory-job.ts`, `components/memory/**` (the slots included), `app/(app)/o/[orgId]/memory/**`; no mount edits |

- **Shared files touched only by phase 1:**
  - `core/config.py`, `app/main.py`, `app/models.py`, `analysis/models.py`, `ops/error_classes.py`;
  - `workers/{celery_app,tasks}.py`;
  - compose files, `.env.example`, `package.json`, `infra/redis-broker/entrypoint.sh`, `scripts/lane-test.sh`;
  - `packages/py-jobs/**`, `packages/py-worker-kit/**`, `packages/contracts/**` (generated after phase 1, then after the merge);
  - `apps/workers/static/static_worker/detections/iocs.py` (the shim);
  - `apps/workers/memory/{Dockerfile,pyproject.toml,uv.lock}`, `memory_worker/{celery_app,config}.py`;
  - `apps/web/lib/{nav,audit-actions,http-errors}.ts`, the analyzer badge, the three slot mounts, the `IocsTab` prop;
  - the analyzer-sweep files (Frozen interfaces 12);
  - the frozen test files.
- **Group B merge (parent):**
  1. Merge the eight worktrees; any conflict is a plan bug.
  2. Full API suite.
  3. `pnpm gen:contracts` with no drift.
  4. `pnpm --filter web test typecheck`.
  5. Rebuild the memory image once (heavy, alone) and run the worker suite with `--heavy`. Every image that copies py-jobs / py-worker-kit (api, pcap, static, report) was rebuilt once after phase 1, one at a time (RT10: the renderer must know the new snapshot field).
  6. Fix seams in the owning files, one commit per phase.
- **Group C: phase 10** (docs) after the merge.
- **Group D: phase 11 last.** It is the only phase allowed to touch other phases' files, and only for gate fixes.
- **One commit per phase.** The stack stays deployable after each:
  - new routes answer 501 until their phase lands;
  - the memory worker fails jobs with `not_implemented`;
  - no memory job is ever created automatically.

### Parallel execution on this host (the M5–M7 lane scheme, `scripts/lane-test.sh`; 4–8 GB free)

1. **One shared infra stack**, started by the parent after the M7 gate: `postgres`, `redis`, `redis-broker`, `minio` (+ init, `db-bootstrap`). Everything else is stopped during group B: web, gateway, the analyzers, report, enrich, analyst and retention workers.
2. **Worktrees** `..\cyber-wt\m8-b{n}` (`-b m8/b{n}` from the phase-1 commit), with `.env` copied in.
3. **Image:** the parent builds `cyberlab/memory-worker:dev` once after phase 1 (heavy, alone; no Go or C++ toolchain is needed: every dependency has a wheel), then the api, pcap, static and report images, one at a time. Lanes never build.
   - **Spike (phase 4, A′):** during phase 1, in worktree `..\cyber-wt\m8-spike` from the M7 merge, on host Python only (a throwaway `uv` venv with `volatility3==2.28.2` in the scratch dir); no container, no slot (RT15).
4. **Worker lanes** (`--service memory-worker-test`, broker db only):
   - phase 2 → lane 2;
   - phase 3 → lane 3;
   - phase 4 → lane 4;
   - phase 5 → lane 5.

   Runs that load an image (the synthetic ones, or the sparse probe-smoke file) add `--heavy`, which takes two of the three slots. Pure unit runs take one.
5. **API lanes:**
   - phase 6 → lane 6;
   - phase 7 → lane 7;
   - phase 8 → lane 8 (`cyberlab_b8_test`, created by phase 1 if missing).

   Run with `scripts/lane-test.sh <lane> uv run pytest -q -p no:cacheprovider <own paths>`.
6. **Never from a lane:** `up`, `down`, `build`, `restart` or `stop`.
7. **Heavy steps (the parent runs each alone, with only the infra stack up):**
   - the memory image build;
   - phase 4's synthetic image engine runs, when more than a smoke test;
   - phase 2's probe smoke on the sparse 8 GiB file (CPU-bound for minutes, no disk);
   - phase 11's fuzz-lite and metrics replay.
   - Never, anywhere: a live `fetch-windows` or any download of a memory image, corpus or symbol pack (parent decision).
8. **Web lane (phase 9):** host `pnpm --filter web test -- <own paths>`, `typecheck`, `lint`. No containers and no slot.
9. **Fallback** when worktrees misbehave on Windows: the M5 fallback (main tree, lane variables in the shell, `python -m compileall` before each run).

## Definition of done

- **Pipeline:**
  - A memory image uploaded with `kind=memory` (≤ 8 GiB by default) can be analyzed on request with `triage` or `full`.
  - The worker verifies the evidence sha256, runs only allow-listed plugins offline, one sandboxed process each, and posts a `memory.v1` stream.
  - The trusted ingest validates it as a whole and writes it in one transaction.
  - A partial run shows per-plugin status and `truncated` flags.
- **Symbols:**
  - No network access happens at analysis time (tested).
  - A missing symbol gives `symbols_missing` with the exact requirement and the operator command.
  - `memory:symbols` fetches (HTTPS, verified, allow-listed; tested against the local mock only), imports operator ISFs and local ISF zips, reindexes at `/symbols` and verifies.
  - The result records the ISF sha256.
- **Sensitivity:**
  - A `kind=memory` upload (or else the first memory job) marks the evidence restricted and AI / TI excluded, and such an upload gets no automatic analysis.
  - Secrets quoted into findings, IOC context and timeline titles are masked.
  - Release is admin-only, acknowledged, audited and once.
  - Reports include restricted memory rows only at TLP:RED.
  - No credential, envars, dump or extraction plugin can run (tested).
- **Detections:** every heuristic behaves as specified on the scenario set (precision / recall table, with the caveat); no heuristic exceeds `medium`; no verdict words.
- **Real engine:** the synthetic Linux image runs end to end (or the recorded no-go and the replay fallback). The probe smoke runs the real Volatility in the worker in every case. Windows is replay-tested and documented as such; the plugin column-drift test passes.
- **Security:**
  - Every new route is in the IDOR enumerator and every new tenant table in RLS coverage.
  - The env checks prove the worker has only the broker URL and read-only symbols, and the symbol tool has only the `symbols_egress` network and the symbol volume.
  - Fuzz-lite ends cleanly, and the probe's audit hook records no network, subprocess or exec attempt.
  - Every two-analyzer branch has a memory arm (`test_analyzer_exhaustive.py`).
- **Gate:** `pnpm verify:prod` is green (the dynamic-gate test included). The e2e covers upload, run, the job page, the restricted banner and the release.
- **Docs:**
  - `docs/MEMORY_FORENSICS.md` (new);
  - ARCHITECTURE, THREAT_MODEL (M8), DATABASE (0015, the §11 mapping), API, DEPLOYMENT (symbols runbook, sizes, disk), TESTING (metrics), ROADMAP, PRD and README updated;
  - the VSL notice and the publishing decision recorded.

## Out of scope

- **Acquisition:** live memory acquisition (WinPmem, LiME, AVML agents), LeechCore, remote collection.
- **Extraction:** process or file dumps, `dumpfiles`, page-cache recovery, carving, credential plugins, `envars`, registry key browsing (`printkey`).
- **Platforms:** macOS (deprecated upstream), ARM64, hiberfil.sys, multi-file VMware snapshots (`.vmss` / `.vmsn` next to a `.vmem`), compressed or archived uploads.
- **Automation:** auto-run on upload, automatic symbol download, a remote ISF server, a bundled symbol pack.
- **AI:** memory-specific AI tasks or prompts (generic AI over memory findings works only after release).
- **Upload:** resumable or multipart direct-to-MinIO upload (ROADMAP "Later").
- **Analysis extras:** timelining with Plaso, disk forensics (TSK / Autopsy), YARA rule management UI, a job-level JSON memory report export, cross-image diffing.
- **Cut by the red team:** YARA scanning of memory (memory-specific rules are "Later"), `windows.handles`, URL-based symbol pack import, the reference corpus (RT8, RT9, RT22).
- **Never:** downloading any third-party memory image or test corpus; a Microsoft symbol fetch from a test, gate or worker (parent decisions).
- **A synthetic Windows image** (no public approach; recorded as "Later").

## Open risks

- **VSL publishing obligation (user's legal decision; parent):** the adapter must be published under the VSL before the platform is made available to others, including as a hosted service. Building and running it for the user's own use carries no such obligation (research §2; not legal advice). M8 keeps the adapter isolated in `apps/workers/memory/` with `NOTICE.md`; docs never paste Volatility source (RT27).
- **Windows not validated on a real image:** no third-party image is used (parent decision), so Windows plugins run only through replay and the column-drift test; the first real Windows run happens on the user's own evidence (operator smoke runbook) (RT4).
- **Symbol coverage:** without symbols for the exact kernel nothing beyond identify runs. The operator workflow is manual, and Linux needs per-kernel dwarf2json builds elsewhere. Mitigated by the diagnostic result and the runbook.
- **Synthetic image feasibility:** the phase-4 spike may fail. Fallback: the replay engine plus the probe smoke; the real engine then never parses a kernel structure in CI (recorded in TESTING and ROADMAP).
- **Volatility on hostile images:** known infinite loops and smear bugs (research §7). Contained by timeouts, `RLIMIT_AS`, caps and the sandbox, not prevented.
- **Disk and RAM on the dev host:** an 8 GiB image holds about 16 GiB of disk at any moment (spool + MinIO during the upload, then MinIO + `/work`), MinIO keeps it at least `EVIDENCE_LOCK_DAYS`, and Docker Desktop's virtual disk does not shrink by itself; tests never upload more than 64 MiB. The memory worker needs 3 GiB. Heavy steps run alone; DEPLOYMENT states the sizing.
- **Contents exposure:** org-wide RBAC means every case reader sees command lines and bash history (THREAT_MODEL residual; per-case ACLs are future work).
- **Plugin drift:** the deprecated plugin shims have passed their removal dates. The pin and the enum isolate us; upgrading Volatility is a deliberate change with fixture re-checks.
