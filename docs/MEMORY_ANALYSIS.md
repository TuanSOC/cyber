# Memory Analysis (Milestone 8, in progress)

> **Status: draft, M8 in progress.** Only the phase-1 foundation is committed (contracts, migration `0016`, compose services, the broker user, the `kind=memory` upload flag, 501 route stubs, a worker that fails every job with `not_implemented`), and **none of it has run in a container yet**. Every section below says what is **built (phase 1, untested)** and what is **pending (phase N)**. Nothing marked pending exists in code. Phase 11 replaces this banner once the gate (`pnpm verify:prod`) is green. Plan: [`plans/261107-0300-cyberlab-m8-memory-forensics/plan.md`](../plans/261107-0300-cyberlab-m8-memory-forensics/plan.md).

The third analysis engine examines uploaded **memory images** (RAM dumps) with [Volatility 3](https://github.com/volatilityfoundation/volatility3), pinned at **v2.28.2**. It reuses the M2 / M3 pipeline unchanged in shape:

1. An isolated, untrusted worker runs an allow-listed set of triage plugins, **one sandboxed process per plugin**, fully offline against a read-only symbol store. It produces a versioned result stream (`memory.v1`).
2. The trusted ingest validates that stream as a whole, then writes it into the memory tables plus the shared findings, IOCs and timeline, in one transaction.
3. The Memory Analysis UI shows the results.

Symbols never come from the internet at analysis time. A separate, trusted operator tool (`memory-symbols`) fetches Windows kernel symbols on request and imports operator-built symbol files. A memory image is treated as **TLP:RED material by default**.

See [PCAP_ANALYSIS.md](PCAP_ANALYSIS.md) for the shared job model and [MALWARE_ANALYSIS.md](MALWARE_ANALYSIS.md) for the static analyzer this one is modelled on.

## Build status

| Area | Phase | Status |
|---|---|---|
| `memory.v1` contract, `MemoryJobV1`, plugin allow-list, `SymbolManifestV1`, contract fixtures | 1 | built, host-tested (`test_memory_contract.py`) |
| Migration `0016`, models, grants, RLS, `memory_sensitivity` trigger | 1 | built, untested in a container |
| Compose: `memory-worker`, `memory-worker-test`, `memory-symbols(-test)`, `symbols_egress`, volumes, broker user `memory` | 1 | built, untested |
| API: `?kind=memory` upload flag (skips auto-run), `analyzer: memory` requests, 501 route stubs, error codes | 1 | built, untested |
| Volatility runner (probe, library mode, audit hook, normalizers), replay engine, probe smoke | 2 | pending |
| Detections, secret masker, scenario dataset | 3 | pending |
| Synthetic Linux image (spike go / no-go) | 4 | pending (spike result not recorded yet) |
| Symbol store, `fetch-windows`, `import`, `reindex`, `verify`, `list` | 5 | pending (the CLI is a stub that exits 2) |
| Memory upload limit, free-space check, upload-time TLP:RED default, dispatch and trusted ingest | 6 | pending |
| Memory read API | 7 | pending (routes answer 501) |
| Sensitivity release, share-policy guard, reports, AI / TI, retention, correlation | 8 | pending (`apply_memory_default` is a no-op) |
| Web: Memory Analysis pages | 9 | pending (slots mounted, empty) |
| Hardening, e2e, fuzz-lite, metrics, gate | 11 | pending |

**Until phase 8 lands, a memory image is not restricted.** `apply_memory_default` is a phase-1 no-op, so AI and TI exclusion must be set by hand through the M6 share policy (or the case TLP set to RED) if a real image is uploaded to a development build.

## When it runs

| Upload | Analysis |
|---|---|
| `POST …/evidence?kind=memory` | **none, of any kind.** The upload skips the automatic pcap / static routing (built, phase 1), so no static `av` scan reads the image (RT3) |
| any other upload | the M2 / M3 automatic routing; memory analysis is never automatic |

- **Always manual.** An analyst runs "Run memory analysis" on the evidence with `analyzer: memory`, a `profile` (`triage`, default, or `full`) and an `os_hint` (`auto`, default, `windows` or `linux`). The API refuses `auto=true` for memory. A run costs minutes to an hour and gigabytes of disk, and raw images have no magic bytes to route on anyway.
- **Images uploaded without `kind=memory`** can still be analyzed. The first memory job applies the same TLP:RED default (pending phase 8); jobs that already ran on the evidence (for example an automatic static `av` scan of a small image) are covered only from then on, and the run dialog says so (pending phase 9).
- **Separate caps.** At most `MEMORY_MAX_ACTIVE_PER_ORG` (1) active memory job per org and `MEMORY_MAX_ACTIVE_TOTAL` (2) on the platform (built, phase 1). They do not share the pcap / static caps.

## Upload and limits

| Limit | Value | Status |
|---|---|---|
| Image size (`MEMORY_MAX_BYTES`) | 8 GiB default; the setting is refused above 16 GiB (RT14) | setting built; the per-kind upload limit is pending phase 6 (until then a `kind=memory` upload is bounded by `MAX_EVIDENCE_BYTES`, 2 GiB) |
| Gateway (`CADDY_EVIDENCE_MAX`) | max(`MAX_EVIDENCE_BYTES`, `MEMORY_MAX_BYTES`) + 1 MiB on the upload route; `.env.example` ships 8 GiB + 1 MiB | built |
| Upload time | Caddy `read_body 30m` (unchanged): 8 GiB needs ≥ 4.6 MB/s sustained, 16 GiB ≥ 9.2 MB/s | as today |
| Empty file | `422 memory_image_empty` when requesting a run | built |
| Too large to analyze | `413 memory_image_too_large` (also on upload, phase 6) | request check built |
| Free disk | the API refuses an upload it cannot spool (`507 insufficient_storage`); the worker refuses a job without size + 1 GiB free (`insufficient_disk`) | pending phases 6, 2 |
| Org quota | unchanged (20 GiB default holds two 8 GiB images) | as today |
| Job | `ANALYSIS_MEMORY_TIMEOUT_S` 5 400 s; per plugin `ANALYSIS_MEMORY_PLUGIN_TIMEOUT_S` 1 200 s; identify `ANALYSIS_MEMORY_IDENTIFY_TIMEOUT_S` 600 s; the reaper adds the M2 grace | settings built |
| Result | ≤ 256 MiB compressed; ingest framing `MEMORY_MAX_RESULT_DECOMPRESSED_BYTES` 1 GiB and lines = the sum of the caps + 3 (RT9) | contract built; ingest pending phase 6 |
| Record caps | processes 20 000, connections 50 000, injections 5 000, artifacts 50 000 (attributes ≤ 4 KiB each), findings 5 000, IOCs 20 000, timeline 5 000; command line ≤ 4 KiB, hex heads ≤ 64 bytes, disassembly ≤ 1 KiB. Every cap hit sets a `truncated` flag | contract built |

The upload is one streaming request, as for every evidence type. Direct multipart upload to MinIO with a server-side re-hash is ROADMAP "Later". Compressed or archived uploads (gzip, bz2, xz, zstd, zip, 7z) are refused by the worker as `unsupported_memory_format` (pending phase 2): Volatility would decompress them transparently, which turns a small bomb into a CPU and disk DoS (RT19).

**Accepted layers** (Volatility 2.28.2): raw / padded, LiME, AVML, ELF64 core, VMware `.vmem` (alone, when it is a raw image) and Windows crash dumps (full and bitmap).

## Pipeline

```mermaid
sequenceDiagram
  participant U as Analyst
  participant A as API
  participant B as redis-broker
  participant W as memory-worker (untrusted)
  participant S as MinIO
  participant I as ingest-worker (trusted)
  participant D as Postgres
  U->>A: upload ?kind=memory (no auto-run; restricted + AI/TI excluded in the upload transaction)
  U->>A: POST analyses {analyzer: memory, profile, os_hint}
  A->>D: job row (queued) + memory default (idempotent) + custody + audit
  A->>B: memory.analyze {MemoryJobV1: presigned GET (exact version), presigned POST, token, limits}
  B->>W: job (queue memory, ACL user memory)
  W->>S: GET image to /work/<job>/input/image (sha256 + size verified, root-owned 0444)
  W->>W: root: magic check (compressed / archive -> unsupported_memory_format)
  W->>W: probe identify (uid 10006): layers, OS, kernel identity, symbol lookup in /symbols
  alt no matching symbols
    W->>S: POST diagnostic memory.v1 (header symbols.required + image line + trailer)
    W->>B: ingest.event failed symbols_missing {result version}
  else symbols found
    loop each allow-listed plugin, fixed order
      W->>W: probe run <plugin> (uid 10006, seccomp AF_UNIX only, audit hook, rlimits, timeout, fresh out dir and cache)
    end
    W->>W: root: bounded reads -> normalize -> detections -> memory.v1 (gzip NDJSON)
    W->>S: POST result (fixed key, size cap)
    W->>B: ingest.event finished {result version}
  end
  B->>I: event (token + org checked against the job index)
  I->>S: GET exact result version, validate every line + trailer
  I->>D: one transaction: memory_* + analysis_findings + iocs + analysis_timeline + custody
```

Status: the message, the queue, the broker user and the worker skeleton are built (phase 1, untested; every job fails `not_implemented`). Everything inside the worker is pending phase 2, the ingest phase 6.

- **States** are the M2 ones: `queued → running → succeeded | failed`, enforced by the database.
- **Job success:** the identify probe and the process list (`windows.pslist` or `linux.pslist`) succeed. Every other plugin is best effort; its status (`ok`, `failed`, `timeout`, `skipped`, `unsupported`), row count, `truncated` flag and duration are in the result header, so a partial run is never shown as complete.
- **Error codes** (`MEMORY_ERROR_CODES`, classified in `ops/error_classes.py`):

  | Code | Class | Meaning |
  |---|---|---|
  | `symbols_missing` | input | no ISF for the image's kernel in the store (an operator gap, not a worker failure; RT25) |
  | `unsupported_memory_format`, `memory_image_too_large`, `memory_image_empty` | input | refused before any probe runs |
  | `memory_parse_failed`, `os_undetermined`, `plugin_failed` | parse | Volatility could not make sense of the image or of a plugin |
  | `symbols_corrupt`, `insufficient_disk`, `identify_timeout`, `plugin_timeout`, `engine_unavailable` | infra | store hash mismatch, disk, time, engine |
  | `not_implemented` | other | the phase-1 skeleton |

## Profiles and plugins

The allow-list is the frozen enum `MemoryPlugin` (19 values, the 2.28.2 names, never the deprecated shims). Nothing outside it can be requested or reported: the result header is refused when it lists another plugin.

| OS | `triage` | `full` adds |
|---|---|---|
| Windows | `windows.info`, `windows.pslist`, `windows.psscan`, `windows.cmdline`, `windows.dlllist`, `windows.netscan`, `windows.malware.malfind`, `windows.svcscan`, `windows.registry.hivelist`, `windows.registry.userassist` | `windows.malware.ldrmodules` |
| Linux | `linux.pslist`, `linux.psaux`, `linux.bash`, `linux.sockstat` | `linux.lsof`, `linux.malware.malfind`, `linux.malware.check_syscall`, `linux.malware.hidden_modules` |

**Never run** (absent from the enum; phase 2 adds a test that the runner cannot load them):

| Plugin or option | Why |
|---|---|
| `windows.registry.hashdump`, `lsadump`, `cachedump` | credential dumpers: collecting password hashes and secrets is out of scope (collection minimisation) |
| `windows.envars` | environment blocks routinely hold tokens and passwords |
| registry `printkey` | arbitrary registry browsing, same reason |
| any `--dump`, `windows.dumpfiles`, `windows.memmap --dump`, the `-o` output dir | M8 extracts no files from memory; a refusing file handler backs this up (RT20) |
| `linux.pagecache.*` | file recovery with a known tar-slip issue (upstream PR #1996) |
| `windows.handles` | cut by the red team: up to 100 000 rows of low triage value, which alone broke the ingest caps (RT9) |
| `windows.vadyarascan`, `yarascan.YaraScan`, `linux.vmayarascan` | cut (RT8): the M3 YARA rules are file rules anchored on `pe.*` / `MZ` and mean nothing on memory chunks; no YARA engine is installed |

## Isolation

The M2 table applies unchanged (credentials, network, privileges, filesystem, persistence, broker, integrity); see [PCAP_ANALYSIS.md](PCAP_ANALYSIS.md#isolation-of-the-parser). What M8 adds:

| Layer | Control | Status |
|---|---|---|
| Container | `analysis` network only, env `BROKER_URL` only (broker user `memory`), read-only rootfs, `cap_drop: ALL` + the analyzers' 6 caps, no-new-privileges, `pids_limit 256`, `mem_limit 3g`, 2 CPUs, tini init; `/work` is the named volume `memory_work` (images are GiBs), `/symbols` is mounted **read-only** | built (compose), untested |
| Tool uid | **10006** (`CYBERLAB_TOOL_UID` / `GID` in the image), not the pcap / static 10003 or the renderer's 10004: `RLIMIT_NPROC` counts every process of a uid on the host (RT18) | built (image), untested |
| One process per plugin | every plugin re-runs the layer stacking in its own process with a fresh out dir, so a crash, hang or compromised parser in one plugin cannot alter another plugin's output (the M3 "fresh out dir per engine" rule) | pending phase 2 |
| seccomp | `unix_sockets_only=True` and `deny_io_uring=True`: only AF_UNIX sockets, no io_uring (the kit's default filter leaves AF_NETLINK / AF_VSOCK open, RT7) | pending phase 2 |
| rlimits | `RLIMIT_AS` `MEMORY_PLUGIN_RLIMIT_AS` (2.5 GiB) and `RLIMIT_FSIZE` 512 MiB per plugin, `oom_score_adj=1000`, timeouts per plugin and per job | setting built; enforcement pending phase 2 |
| Offline library mode | the probe drives `volatility3.framework` directly, never the CLI: `constants.OFFLINE = True`, `REMOTE_ISF_URL = None`, a fixed per-plugin configuration, no plugin dirs beyond the built-in ones | pending phase 2 |
| Symbol path list | exactly `["/symbols", <volatility3/symbols>, <volatility3/framework/symbols>]`: our store first, then the two read-only bundled directories (netscan, PE, bash and generic type tables, RT2). The writable cache fallback is dropped, so a converted PDB can never be written anywhere | pending phase 2 |
| Audit hook | a PEP 578 hook installed after the imports refuses and counts `socket.*`, `urllib.Request`, `subprocess.Popen`, `os.exec*`, `os.system` and `os.spawn*`; the counts go into the result header (`audit_events`) and phase 11 asserts zero | contract field built; hook pending phase 2 |
| Refusing file handler | a `FileHandlerInterface` passed as `open_method` refuses every write, whatever a plugin's options (RT20) | pending phase 2 |
| `HOME` and config dirs | `HOME` and `XDG_CONFIG_HOME` are `/nonexistent`; each plugin gets a fresh tool-owned `XDG_CACHE_HOME`, seeded from the store's read-only identifier cache and thrown away after it (upstream bugs #2050 / #2042; one plugin cannot poison the next) | env built; cache seeding pending phase 2 |
| Read-only code | site-packages is root-owned, so a tool process cannot plant a plugin or patch Volatility; no `-p`, no `vol.json` config | built (`docker/finalize_image.py`), untested |
| Forbidden packages | the build fails if `volatility3[full]` extras, `leechcorepyc`, `pycryptodome`, `pillow`, `pysmb`, `yara-python` or `yara-x` is importable | built, untested |
| Output | the TreeGrid is streamed by our own visitor with per-kind caps and stopped at the cap (Volatility's JSON renderers buffer the whole result); root reads tool output with bounded readers and per-plugin row models | pending phase 2 |
| Replay engine | `MEMORY_ENGINE=replay` (hand-written rows) is refused unless `TEST_PROFILE=1`, and every result it produces says `engine: replay` (`requirement.txt` §16) | config check built; engine pending phase 2 |

## Symbols

Volatility needs a symbol table (ISF) matching the exact kernel of the image. By default it would download Windows PDBs from `msdl.microsoft.com` over plain HTTP, retrying with TLS verification off. In CyberLab **the worker never reaches the internet**: it is on `analysis` only, its tools cannot open inet sockets, and Volatility is set offline in code.

**The image ships no symbols.** This keeps it small and avoids redistributing ISF derived from Microsoft PDBs, whose terms are unverified.

### The store (pending phase 5; volumes built)

The named volume `memory_symbols`, written only by `memory-symbols` (uid 10005) and mounted read-only into the worker at `/symbols`:

```
/symbols/
  windows/<pdb>/<GUID-AGE>.json.xz
  linux/<sha256>.json.xz
  manifest.json                          SymbolManifestV1: per file its sha256, OS, identity,
                                         source (msdl | operator | zip:<sha256>), tool version,
                                         imported_at; `identifier_cache_sha256` of the cache
  .cache/volatility3/identifier.cache    prebuilt by `reindex` (file:///symbols/... locations)
```

Before using a file, the worker re-checks its sha256 against the manifest (`symbols_corrupt` on a mismatch). After the probes it re-hashes every store ISF they report loading: a file the manifest does not list, a changed file, or an ISF from anywhere but the store and Volatility's own symbol dirs fails the job `symbols_corrupt`. A probe's identifier cache is seeded only when the manifest records its sha256 and the copy hashes to it (else no cache: Volatility indexes the store itself; a mismatch is `symbols_corrupt`). The result header records the sha256 of the ISF the run actually loaded, the Volatility version and the engine, so a run can be reproduced.

Every probe's output counts against a per-job budget (768 MiB of the 1 GiB headroom) and must leave 256 MiB free on `/work` for the result; otherwise the job fails `insufficient_disk` before the next probe. A probe that leaves no `status.json` (killed on timeout) is not offline-verified: its rows are dropped and the plugin is shown partial. The job's time budget starts before the image download.

### Missing symbols: a diagnostic result

The identify probe reads the kernel identity from the image without symbols: the PDB name, GUID and age on Windows, the kernel banner on Linux. With no matching ISF, the worker uploads a small diagnostic `memory.v1` stream (header with `symbols.status = missing` and `symbols.required`, an image line, the trailer) and the job fails `symbols_missing`. The ingest stores only that requirement in `memory_images`.

The job page then shows (pending phase 9):
- **Windows:** the exact command for an operator, built in the browser from the validated fields only (kernel PDB allow-list, 32 hex digits, age range);
- **Linux:** the banner as quoted, inert text with a link to the runbook, and **never a command containing it**: the banner is attacker-chosen text, and a pasted command would be command injection on the operator's host (RT12);
- members without `org.update`: "ask your operator";
- "Re-run" on every `symbols_missing` job (the API cannot see the store).

**The fetch is never automatic.** The GUID comes from attacker-controlled bytes, and a fetch tells a third party which build is being investigated, so an operator decides.

### Operator workflow (pending phase 5)

The commands run the trusted `memory-symbols` tool (compose profile `tools`, its own `symbols_egress` network only). The CLI is a stub that exits 2 until phase 5 lands.

```bash
# What is in the store
pnpm memory:symbols -- list

# A Windows job failed symbols_missing: copy the command from the job page, e.g.
pnpm memory:symbols -- fetch-windows --pdb ntkrnlmp.pdb --guid 0123456789ABCDEF0123456789ABCDEF --age 1

# A Linux kernel: build the ISF elsewhere (dwarf2json on a machine with the matching
# debug kernel), put it in ./.memory-import/ (mounted read-only at /import), then
pnpm memory:symbols -- import --file /import/linux-5.15.0-91-generic.json.xz

# A local zip of ISFs (members checked for traversal, symlinks, type, count and size)
pnpm memory:symbols -- import --file /import/windows-isf.zip --sha256 <expected sha256>

# After any import, and after a restore
pnpm memory:symbols -- reindex
pnpm memory:symbols -- verify

# The test store (used only by the phase-11 pipeline run)
pnpm memory:symbols -- --store test list
```

Then re-run the job. Details, the redirect host list and the backup advice: [DEPLOYMENT.md](DEPLOYMENT.md#memory-forensics-m8).

## Result contract `memory.v1`

`packages/py-jobs/src/cyberlab_jobs/memory.py` (built, phase 1; host-tested with `test_memory_contract.py` and the fixtures in `packages/py-jobs/tests/fixtures/memory/`). A gzip NDJSON stream:

| Line | Content |
|---|---|
| header (first) | `job_id`, `profile`, `os`, `engine` (`volatility3` \| `replay`), `tool_versions`, `symbols` {`status`, `isf_sha256?`, `required?`: `WindowsPdb{name, guid, age}` \| `LinuxBanner{banner}`}, `plugins[]` {`plugin`, `status`, `rows`, `truncated`, `duration_ms`, `error_code?`} ⊆ the profile's allow-list, `audit_events`, `engine_errors`, `truncated` |
| `image` | `size_bytes`, `sha256` (must equal the evidence record), `layer`, `arch` (`x86` \| `x64`), `nt_build?`, `pdb?`, `kernel_banner?`, `system_time?` |
| records | `process`, `connection`, `injection`, `artifact` (types `module`, `service`, `hive`, `userassist`, `ldr_unlinked`, `bash`, `open_file`, `syscall_hook`, `hidden_module`; scalar attributes only, ≤ 4 KiB) |
| shared | `finding`, `ioc` (the M2 / M3 records), memory timeline events (`system_time`, `process_start`, `process_exit`, `connection`, `finding`) |
| trailer (last) | the M3 trailer with counts and hash |

- Addresses are unsigned 64-bit (`NUMERIC(20,0)` in the database); text is bounded, NUL-free; floats are refused in attributes.
- A **diagnostic stream** (`symbols_missing`) is header + at most an image line + trailer, and its header lists no plugin run.
- Hostile fixtures cover a wrong job id, NaN, NUL, oversize command lines, 33 attributes, nested or float attributes, extra fields, an unknown plugin, address overflow, a verdict-level severity, a bad GUID, a non-kernel PDB, banner control characters, lines after the trailer, a missing trailer and a diagnostic stream with records.

## Findings (never verdicts; pending phase 3)

Deterministic heuristics over the **normalized** records (never raw plugin output). Windows unless noted.

| Method | Fires on | Max severity |
|---|---|---|
| `heuristic:mem_hidden_process@1` | a process seen by `psscan` but not `pslist`, with no exit time and threads > 0 | medium |
| `heuristic:mem_injected_code@1` | a private, executable, writable `malfind` region; `medium` with an `MZ` / in-bounds PE header, `low` otherwise; known JIT hosts without a PE header skipped. Titles say "private executable memory region", never "injected code" (RT21) | medium |
| `heuristic:mem_process_lineage@1` | core-process parent rules (`smss`, `wininit`, `csrss`, `services`, `lsass`, `svchost`) and duplicate singletons; a **missing** parent never fires (RT21) | medium |
| `heuristic:mem_masquerade@1` | a name at edit distance 1–2 from a core process name, or a core name running from outside `System32` / `SysWOW64` | medium |
| `heuristic:mem_suspicious_cmdline@1` | encoded or hidden PowerShell, download cradles, `certutil -urlcache`, `bitsadmin /transfer`, `mshta http`, `rundll32 javascript:`, `regsvr32 /i:http`, `wmic process call create` | medium (`low` for one weak pattern) |
| `heuristic:mem_unlinked_module@1` (`full`) | an `ldrmodules` entry missing from all three loader lists, with a mapped path | medium |
| `heuristic:mem_service_path@1` | a service binary under a user-writable path or a driver outside `System32\drivers`; a constant exclusion list for vendor platform paths (Defender, RT21) | low |
| `heuristic:mem_unexpected_network@1` | an established external connection owned by a process that normally has none | medium |
| `heuristic:mem_linux_shell_history@1` (Linux) | bash history with download-and-execute or reverse-shell patterns | medium |
| `heuristic:mem_correlated_indicators@1` | a process with two or more of hidden / injected / lineage / masquerade / unexpected network; refs the others, never raises them | medium |

- **Nothing reaches `high`.** M8 has no signature method (memory YARA is cut, RT8), and heuristics cap at `medium`.
- **Wording.** Templates describe what was observed, with the measured values; a test rejects verdict words.
- **IOCs** (observables only): connection remote addresses, and URLs / domains / IPs in command lines and bash history, through the shared extractor `cyberlab_worker.iocs` (built, phase 1: lifted verbatim from the static worker).
- **Timeline:** image system time, process creates and exits, connection creation times and findings, at most 5 000 events.

## Sensitivity: TLP:RED by default (pending phases 6, 8)

A memory image holds whatever the machine held: passwords and hashes, session tokens, private keys, mail, documents, chat.

- **Default.** A `kind=memory` upload (in the upload transaction), or else the first memory job on an evidence item, inserts `memory_sensitivity` = `restricted` and sets the evidence's M6 share policy to `ai_excluded = ti_excluded = true`, never loosening an existing policy. Idempotent; audited `memory.sensitivity_defaulted`. The table, its trigger and the audit action names are built (phase 1); the logic is pending (phase 8, called by phase 6).
- **Release.** `POST …/evidence/{id}/memory-sensitivity/release` (`org.update`, body `{acknowledge: true, reason}`) moves `restricted → released` **once** (the trigger refuses anything else), audited `memory.sensitivity_released`. It does not clear the share-policy flags: the analyst then uses the M6 share-policy route as usual. While the evidence is restricted that route refuses to clear a flag (`409 memory_sensitivity_restricted`).
- **Secret masking** (RT13, phase 3). Text quoted from command lines and bash history into findings, IOC context and timeline titles passes a deterministic masker (`password=`, `-p<value>`, `/user:<u> <pw>`, `Authorization: Bearer`, `--token` / `--secret` / `--api-key`, AWS key shapes, private-key headers) that keeps the first 2 characters and the length (`P@********(10)`). These are the surfaces that reach the M7 search index, reports, correlation and, after release, AI. The raw text stays only in `memory_processes.cmdline` and `memory_artifacts`, on the job pages (`evidence.read`).
- **Collection minimisation.** No credential plugins, no `envars`, no dumps, no file extraction. Command lines and bash history are kept (core triage value) and are visible to every member with `evidence.read` (org-wide RBAC; a residual in [THREAT_MODEL.md](THREAT_MODEL.md#m8-memory-forensics)).

### How it plays with the rest of the platform (pending phase 8)

| Module | Behaviour for restricted memory evidence |
|---|---|
| AI analyst (M5) | AI runs on the memory job answer `409 policy_blocked`; incident summaries skip it (`context_stats.policy_excluded`); the analyst worker re-checks before every provider call. After release + share-policy PUT, a memory job's AI digest is its findings and IOCs only (masked), never a pcap summary. No memory-specific AI task |
| Threat intel (M4) | job-scope enrichment answers `409 policy_blocked`; the job page shows no "Enrich" button while restricted (`IocsTab.enrichDisabledReason`, built in phase 1). Manual lookups carry no case scope (the M6 residual) |
| Reports (M6) | memory-derived rows of restricted evidence (findings, IOCs, timeline entries, the memory summary) are included only when the report's TLP is `red`. Otherwise they are left out and counted in the additive snapshot field `omissions.memory_restricted` (built in `cyberlab_jobs/report.py`, phase 1, with a golden test proving existing signed snapshots keep their bytes); the renderers print "N memory items omitted (restricted evidence; TLP:RED required)" |
| Retention (M7) | `memory_processes`, `memory_connections`, `memory_injections`, `memory_artifacts` are bulk derived rows, purged for closed cases after `closed_case_days` (cited rows kept); `memory_images`, `memory_sensitivity`, findings and IOCs are never purged. The image bytes are evidence bytes and follow the M7 evidence purge. The retention DELETE grants are built (0016); `BULK_TABLES` is phase 8 |
| Correlation (M7) | allowed inside the org: memory IOCs are `iocs` rows, so the indexer picks them up (keys only, never across orgs). "Also seen in" links a memory job to `/memory/{job}` (analyzer sweep, built in phase 1) |
| Search (M7) | finding titles and descriptions are indexed, hence the masker above |
| Metrics (M7) | `job_outcomes.kind` gains `memory` (built, 0016); `symbols_missing` counts as an input error, not a worker failure (RT25) |

## Real-engine coverage

No third-party memory image is downloaded, by any tool, test or gate (`requirement.txt` §14: no real malware; parent decision). That includes the `volatility3-test-data` images and their symbol packs. No Microsoft symbol fetch happens in a test or gate either. So:

| OS | Coverage | Status |
|---|---|---|
| Linux | the real Volatility runs `linux.pslist` (stretch: `psaux`, `sockstat`) end to end on a **synthetic** 16–32 MiB image generated at test time with our own minimal ISF, or, on a no-go, only the probe smoke below | pending phase 4 (10 h spike; go / no-go not recorded yet) |
| Windows | **replay-tested, not validated on a real image in CI.** Windows plugins are covered by our hand-written row fixtures, the test-only replay engine and a column-drift test that reads each allow-listed plugin's `TreeGrid` columns from the installed 2.28.2 source | pending phase 2 |
| Both | **probe smoke:** the real Volatility runs in the worker on a random 16 MiB blob and on a sparse 8 GiB file in the test tmpfs (never uploaded); identify ends `os_undetermined` within its timeout, offline mode and the audit hook are active, no socket attempt is recorded, and RSS stays below `RLIMIT_AS` | pending phase 2 |

The first real Windows run therefore happens on the operator's own evidence: [DEPLOYMENT.md](DEPLOYMENT.md#memory-forensics-m8) has a manual smoke procedure (never automatic).

## Synthetic scenario set and quality

Scenarios are generated `MemoryView`s (benign baselines: a Windows 10 workstation, a Windows Server, a Linux server; labelled positives and benign near-misses), built at test time and never committed as output (phase 3).

| Detector | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| mem_hidden_process | pending — filled by phase 11 | | | | |
| mem_injected_code | pending — filled by phase 11 | | | | |
| mem_process_lineage | pending — filled by phase 11 | | | | |
| mem_masquerade | pending — filled by phase 11 | | | | |
| mem_suspicious_cmdline | pending — filled by phase 11 | | | | |
| mem_unlinked_module | pending — filled by phase 11 | | | | |
| mem_service_path | pending — filled by phase 11 | | | | |
| mem_unexpected_network | pending — filled by phase 11 | | | | |
| mem_linux_shell_history | pending — filled by phase 11 | | | | |
| mem_correlated_indicators | pending — filled by phase 11 | | | | |

Also pending, filled by phase 11 (`plans/reports/memory-metric-YYMMDD.md`): IOC recall, parsing success, analysis latency, worker failure rate, the fuzz-lite outcome and the synthetic-image result.

**Caveat:** these will be synthetic numbers on scenarios designed alongside the detectors. They show that the detectors behave as specified, not real-world detection quality. Malfind and lineage rules are known to be noisy on real systems (JIT hosts, security products, exited parents).

## Limitations

- **Not validated on a real Windows image in CI** (above). Volatility's robustness on hostile or smeared images is limited (known infinite loops and smear bugs): contained by timeouts, `RLIMIT_AS`, caps and the sandbox, not prevented.
- **Symbol coverage.** Without an ISF for the exact kernel nothing beyond identify runs. The workflow is manual; Linux needs a per-kernel dwarf2json build done elsewhere.
- **Platforms out of scope:** macOS (deprecated upstream in 2.28.2), ARM64 (not merged upstream), `hiberfil.sys` (no upstream layer), VMware `.vmss` / `.vmsn` next to a `.vmem` (a job has one evidence file), compressed or archived uploads.
- **No extraction:** no process or file dumps, no page-cache recovery, no carving, no credential plugins, no `envars`, no registry browsing.
- **No YARA over memory** and no `windows.handles` (RT8, RT9).
- **Single-request upload** of up to 16 GiB through Caddy's 30-minute body timeout; no resume.
- **One process per plugin** repeats the layer stacking for each plugin (seconds to about a minute each); combining cheap plugins is "Later".
- **Contents exposure:** every case reader sees command lines and bash history (org-wide RBAC); secrets are masked on the shared surfaces only.
- **Plugin drift:** an upgrade of Volatility is a deliberate change with fixture re-checks; the pin and the enum isolate the platform from renamed plugins.

## License: Volatility Software License v1.0

**Not legal advice.** This section summarises facts about the licence and how the repository is arranged around it; the decision on publication belongs to the repository owner.

- **What is used.** `volatility3==2.28.2`, installed unmodified from PyPI into the memory worker image, under the [Volatility Software License (VSL) v1.0](https://www.volatilityfoundation.org/license/vsl-v1.0). The image keeps the wheel's `LICENSE.txt` at `/usr/share/doc/volatility3/LICENSE.txt` and [`apps/workers/memory/NOTICE.md`](../apps/workers/memory/NOTICE.md) at `/usr/share/doc/cyberlab-memory/NOTICE`.
- **What the VSL says, in summary** (see the licence text itself and the [research report](../plans/reports/researcher-261107-m8-volatility3.md#2-license-volatility-software-license-v10)):
  - redistributing the unmodified software is allowed when the licence (or its link) reaches every recipient and copyright notices are kept;
  - "Additions" include changes and ports, and "any software designed to execute the software and parse its results, such as a wrapper"; the VSL also counts content or materials, including training materials, that contain any portion of the software;
  - Additions made available to others, by copies **or over the Internet**, must be made publicly available under the VSL.
- **How CyberLab is arranged.**
  - Every Volatility-specific line (probe, normalizers, engines, the symbol tool) lives in `apps/workers/memory/`, which the NOTICE describes as an Addition.
  - Volatility is never patched.
  - The `memory.v1` contract, the trusted ingest, the API and the web UI are tool-agnostic.
  - The docs link to upstream and never paste Volatility source; fixtures and row shapes are our own (RT27).
  - `leechcorepyc` (GPLv3), `pycryptodome`, `pysmb` and the YARA engines are deliberately not installed.
  - Other dependencies of the worker: `pefile` (MIT), `capstone` (BSD-3-Clause), `jsonschema` (MIT).
- **Open decision (repository owner).** Running CyberLab for your own use creates no publication obligation. Before the platform is offered to anyone else, including as a hosted service, decide whether to publish `apps/workers/memory/` under the VSL. The plan recommends publishing that directory under the VSL, alongside whatever licence is chosen for the rest of the repository, which has no licence file today. Recorded in [ROADMAP.md](ROADMAP.md) and the [README](../README.md#third-party-software-and-licenses).
- **Microsoft symbols.** ISF converted from Microsoft PDBs stays in the local symbol store and is never part of an image or a backup the platform ships; the redistribution terms of PDB-derived ISF are unverified.
