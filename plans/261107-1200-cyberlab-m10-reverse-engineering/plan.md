---
title: "CyberLab M10 Reverse Engineering"
description: >-
  Reverse engineering of PE / ELF samples with Ghidra 12.2 headless (PyGhidra library mode,
  JDK 25) as a fourth untrusted analyzer on the M2/M3 pattern: an isolated, network-less
  re-worker that imports one sample through an explicitly chosen loader, runs bounded
  auto-analysis, exports functions, call graph, imports usage and string references, and
  decompiles a deterministic priority list of functions to pseudo-C (per-function and total
  size caps), each stage one sandboxed JVM process (tool uid, seccomp AF_UNIX-only, rlimits,
  cgroup cap). radare2 6.2.6 adds an optional, cuttable `quick` profile (no decompilation).
  A versioned `re.v1` contract; trusted ingest into new `re_*` tables plus the shared
  findings and IOCs; capa capabilities linked to functions through an additive, address-
  carrying `static.v1` field. Samples are never executed. Decompiled code and names are
  untrusted text: bounded, rendered as text with a linear tokenizer, and sent to the AI only
  through the M5 transforms in a new verdict-free `explain_function` task citing function
  and code items. Synthetic benign C programs (the M3 mingw samples plus RE fixtures with
  compiler ground truth) give real-engine tests and function-recovery precision / recall.
  A time-boxed Ghidra-in-sandbox spike runs first. Red-teamed 2026-11-07 (32 findings,
  24 accepted).
status: pending
priority: P2
effort: 189h
branch: "feat/m10-reverse-engineering"
tags:
  - feature
  - reverse-engineering
  - ghidra
  - radare2
  - analyzer
  - security
blockedBy: [261107-1200-cyberlab-m9-disk-forensics]
blocks: []
created: "2026-11-07T12:00:00.000Z"
createdBy: "ck:plan"
source: skill
---

# CyberLab M10 Reverse Engineering

## Overview

**Requirements this milestone covers** (`requirement.txt`):
- §1 and §3: "Reverse Engineering", "Ghidra", "Ghidra headless analyzer", "radare2".
- §4: the `reverse_engineering` module with a clear interface and a versioned job schema; "the web API must never execute untrusted files directly".
- §6: functions, imports and strings of the M3 static analysis, now at function granularity ("Do not treat suspicious imports … as proof of malware" still holds: heuristics cap at `medium`, no verdict words).
- §9: "Explain malware static findings" extended to one function, with evidence citations; observed / interpretation / hypothesis / confidence / next step.
- §12: the "Reverse Engineering" navigation item (a planned placeholder today, segment `reverse-engineering`).
- §13: secure uploads, file size limits, **parser vulnerabilities**, **prompt injection**, **sandbox escape assumptions**, evidence integrity, data retention.
- §14: parsing success, analysis latency, detection precision / recall (here: function recovery and the RE heuristics), worker failure rate; "Do not distribute real malware samples".
- §16: "Do not use mock results as real analysis findings": the replay engine is test-profile only and labelled.

**Inputs:**
- ROADMAP "Later" ("reverse engineering (Ghidra headless, radare2)");
- the coverage audit `plans/reports/requirements-coverage-261106.md` (rows "Ghidra / headless, radare2" and `reverse_engineering`: Deferred);
- the research report [`plans/reports/researcher-261107-m10-reverse-engineering.md`](../reports/researcher-261107-m10-reverse-engineering.md);
- the M8 plan (`261107-0300-cyberlab-m8-memory-forensics`), whose structure, sandbox choices and red-team findings this plan reuses (library-mode driving, own tool uid, unix-only seccomp, per-container test tmpfs, analyzer sweep, exhaustiveness tests);
- `docs/MALWARE_ANALYSIS.md`, `docs/AI_ANALYST.md`, `docs/THREAT_MODEL.md` (M2, M3, M5 sections), `docs/ARCHITECTURE.md`.

**What exists today (scout, 2026-11-07, working tree at M7 + M8 / M9 plans):**
- **Alembic head:** `0015_m7_hold_sync`. M8 adds the next revision, M9 the one after. **M10 takes head + 1 after the M9 merge (expected `0018`)**; phase 1 confirms.
- **Analyzers:** `analysis/models.py:Analyzer` (`pcap`, `static`; M8 adds `memory`, M9 its disk value). Per-analyzer parameters in `analysis/analyzers.py`; auto-run in `analysis/service.py:auto_choice`.
- **Static (M3):**
  - `static.v1` (`packages/py-jobs/src/cyberlab_jobs/static.py`): `CapabilityRecord{name, namespace, attack, mbc, matches}` has **no addresses**; `ImportRecord`, `ExportRecord`, `StringRecord` are file-level.
  - The capa engine (`static_worker/engines/capa.py`) runs `capa -j` and reduces the JSON in the tool-uid `capa` probe mode; capa's document carries `matches: tuple[(Address, Match)]` per rule (research §8).
  - `malware_capabilities` (`static_analysis/models.py`): `name`, `namespace`, `attack`, `mbc`, `matches`; addresses elsewhere are `NUMERIC(20,0)`.
  - Samples: `apps/workers/static/samples/c/{hello,injector}.c`, cross-compiled with mingw-w64 at test time in the static dev image (`generate.py:compile_c`, never run); pure-Python PE / ELF builders `samples/{pe,elf}.py`; adversarial twins with prompt-injection payloads (`samples/inject.py`).
- **Worker kit:** `sandbox.run_tool(argv, dirs, *, timeout_s, extra_env, memory_bytes | rlimits=Rlimits(as_bytes, cpu_s, fsize_bytes, nofile, nproc), deny_io_uring, unix_sockets_only)`; tool uid from `CYBERLAB_TOOL_UID` (10003 analyzers, 10004 renderer; M8 takes 10005 / 10006, M9 10007 / 10008); `nproc` defaults to unlimited, `nofile` to 1024, **`cpu_s` to the wall timeout** (RLIMIT_CPU counts the CPU of every thread of the process); env `HOME` / `XDG_CONFIG_HOME` / `TMPDIR` = the out dir, nothing inherited. seccomp is allow-by-default and filters only `socket` / `socketpair` (and io_uring when asked); every filter and rlimit is inherited across `fork` / `execve`.
- **Heavy analyzers' memory** (`mem_limit`): pcap 2g, static 3g, report 1g, M8 memory 3g, M9 disk 3g, M10 RE 4g: their sum is above the 8–12 GB Docker VM, and no cross-analyzer admission control exists today (RT2).
- **Contract base:** `Strict` is `extra="forbid"`: an older reader refuses a stream with a new field (RT18). `CapabilityOut` is also the item type of the static JSON report's `ReportCapabilities` (RT6).
- **M3 API sets** (`static_worker/detections/apis.py`): `ApiSet{groups, any_of}` with A / W variants and the pseudo-API `string:run_key`; a set fires when every group of one `any_of` combination is present (RT7).
- **AI (M5):** `AiTask` (`explain_finding`, `explain_alert`, `summarize_pcap`, `explain_static`, `ioc_correlation`, `attack_mapping`, `incident_summary`, `job_digest`); label prefixes J F A N R I T E K V M D S C P X; **every string field truncated to 256 characters** by the transforms; templates pinned by sha256 to `PROMPT_VERSION` (`m5.1`, bumped on any template change; M8 and M9 add no AI task or template, so M10 takes `m10.1`); deterministic verifier with quotes ≥ 8 characters and salient-token anchoring.
- **Gates:** `tests/unit/test_dynamic_gate.py` forbids the words `dynamic` / `sandbox` in analyzer values, queues, task names, broker users and compose service names.
- **Web:** `lib/nav.ts` entry `key: "re"`, segment `reverse-engineering`, `plannedFor`; Malware Lab `/o/{org}/malware/{job}` (`components/malware/*`).
- **M8 / M9 dependencies assumed** (phase 1 verifies after the M9 merge): the analyzer sweep pattern and `test_analyzer_exhaustive.py` (M8 RT1), `cyberlab_worker.iocs` (the lifted IOC extractor, M8), `scripts/lane-test.sh --service … --heavy` (M8), lane DB `cyberlab_b8_test`.

Decisions taken by the planner are marked **(decision)**. The red-team pass of 2026-11-07 changed them where its table says so (RT ids in the text).

## Architecture (decided)

    analyst: Malware Lab static job (succeeded, profile full, file_format pe|elf) -> "Reverse engineer"
             {profile quick|full, optional decompile_addresses[] (full)}            (never automatic)
      -> API: checks (size ≤ RE_MAX_BYTES, x86/x64 by the static facts, per-org cap, the global
              heavy-analysis cap over memory / disk / reverse (RT2), share policy untouched)
              -> job row (analyzer reverse, source_job_id = that static job) + custody + audit
              -> capa RVAs of the source job (validated ints from malware_capabilities.locations)
      -> redis-broker queue `reverse` (ACL user `reverse`) -> reverse.analyze {ReJobV1}
    re-worker (UNTRUSTED, analysis network only, broker URL only, mem_limit 4g, concurrency 1)
      -> GET exact evidence version (presigned) -> /work/<job>/input/sample, sha256 + size verified, 0444
      -> root: magic check (MZ+PE / ELF; CLR header -> unsupported_managed_code; else unsupported_format)
      -> root: free-space check; a disk watchdog and a cgroup memory poller run during every stage (RT5, RT14)
      -> stage `analyze` (uid 10010, one JVM): PyGhidra start (pinned launch.properties + our vmargs,
         audit hook installed once the JVM is up, RT1), project in a fresh
         tool-owned dir, import with PeLoader|ElfLoader only (no library loading, no external
         debug files), auto-analysis with our option set under a timeout monitor, export:
         program facts, functions, call edges, imports + refs, strings + refs -> bounded JSONL
      -> root: bounded reads, contract validation, caps -> decompile priority list (deterministic)
      -> stage `decompile` (uid 10010, a second JVM with a smaller heap, program opened without
         saving): DecompInterface (comments off), the native child's RLIMIT_AS lowered by prlimit
         (RT4), per-function timeout, per-function and total byte caps -> bounded JSONL
      -> [profile quick instead: stage `r2` (uid 10010): one non-interactive `radare2 -q -NN -S -2
         -i <fixed script>` run, output to a bounded file, reduced by a probe; no r2pipe, no
         decompilation (RT9)]
      -> root: detections (function-level API sets, run-time API resolution, IOC strings in code)
         -> re.v1 (gzip NDJSON: header, program, records, findings, iocs, trailer)
      -> presigned POST (fixed key, size cap) -> ingest.event finished
    ingest-worker (trusted): token + org from the job index -> validate the whole stream
      -> one transaction: re_* tables + capa↔function links (join on file virtual addresses with
         the source job, RT8)
         + analysis_findings + iocs + custody

**Engine choice** (decision; research §6)
- **Primary: Ghidra 12.2** (2026-10-22; JDK 25; Apache-2.0) driven by **PyGhidra 3.2 in library mode** (`pyghidra.start`, `open_project`, `program_loader`, `analyze`, then the Java API from Python). Reasons:
  - decompiled pseudo-C is the core value for the analyst and for the AI task; radare2 has no decompiler without the r2ghidra C++ plugin build;
  - loaders and analysis are memory-safe Java (DoS possible, memory corruption unlikely); radare2 is C with a steady stream of parser memory-safety fixes (6.2.6 notes);
  - no command language: nothing an attacker-chosen symbol name can inject into;
  - `requirement.txt` names "Ghidra headless analyzer";
  - Apache-2.0: no copyleft reaches our adapter (unlike M8's VSL).

  Cost: an image of ≈ 1.6–1.9 GB untrimmed (target ≤ 1.2 GB after deleting unused modules), a 4 GiB container and minutes per sample. It fits the 8–12 GB host with concurrency 1 and **one active heavy analysis (memory, disk or reverse) at a time across the platform** (`ANALYSIS_HEAVY_MAX_ACTIVE`, default 1, RT2), and heavy test steps run alone.
- **Library mode, not `analyzeHeadless`:** no script path, no run-time script compilation (OSGi), no Jython; our probe writes bounded JSONL directly (the M8 Volatility pattern). **The PyGhidra launcher is not side-effect free** (RT1, verified in `pyghidra/launcher.py`): `start()` may run `LaunchSupport` through `subprocess.check_output(..., shell=True)` and `java -version` to find the JDK, merges the `VMARGS` of `support/launch.properties` into the JVM arguments, and may install Python plugins of Ghidra extensions (with a lock file in `tempfile.gettempdir()`). Therefore: the probe passes the pinned JDK path so no discovery subprocess runs where the launcher allows it (else the two root-controlled helper runs happen before the audit hook and are recorded); the image ships our own reviewed `launch.properties` (root-owned) so the effective argument list is exactly ours; plugin installation finds nothing (trimmed `Extensions/`, read-only site-packages, asserted); the audit hook is installed **after `pyghidra.start()` returns and before the sample is opened**; the probe writes `RuntimeMXBean.getInputArguments()` to `status.json` and root compares it with the expected list.
- **Optional second engine: radare2 6.2.6** (LGPL-3.0, used as a separate process; ≈ 30 MB in the same image) for the `quick` profile: functions, imports and their callers, strings and their referencing functions, call graph; no decompilation; seconds per sample. Driven by **one non-interactive run with a fixed script file** from the image (no r2pipe: it spawns r2 from inside the hooked probe and buffers replies without a bound, RT9). **Cuttable** (phase 3): the profile stays in the frozen enum and the API refuses it with `422 profile_unavailable` while `RE_QUICK_ENABLED=false`.
- **Spike first** (phase 2, part A′, time-boxed 8 h, parallel with phase 1, a heavy step run alone by the parent): Ghidra + PyGhidra + JDK 25 in a throwaway container under the kit sandbox (uid, seccomp AF_UNIX-only + no io_uring, rlimits) on the mingw samples. It fixes the vmargs (and the launcher's side effects, RT1), `RLIMIT_AS` / `CPU` / `NPROC` / `NOFILE`, the decompiler child's `prlimit`, JDK vs JRE, the trim list, the 12.2 analyzer and loader option names and the measured RSS / time. **No-go fallback** (Ghidra cannot run reliably in the sandbox within 4 GiB): radare2 becomes the only engine, `full` = radare2 analysis + bounded disassembly per prioritized function (no pseudo-C), decompilation goes to ROADMAP "Later", `explain_function` sends disassembly instead of code; the contract is unchanged (`engine`, `code_kind`).

**Samples are never executed** (decision): neither engine runs native code. Ghidra's P-code emulator is not used. radare2 never uses the debugger (`ood`, `dc`, `-d`) or ESIL emulation (`aaaa`, `aez*`). The dynamic gate stays green: nothing here is dynamic analysis, and no name contains `dynamic` or `sandbox`.

**Scope** (decision)
- Inputs: one PE or ELF evidence file whose **latest succeeded static `full` job** identified `pe` / `elf` (this guarantees the M3 AV scan and format facts and gives the capa links); otherwise `409 static_analysis_required`.
- Architectures: x86 and x86-64 only (Ghidra processors other than `x86` and `DATA` are deleted from the image); anything else → `unsupported_architecture` (diagnostic). ARM / AArch64 / MIPS go to "Later".
- Refused: .NET / managed PE (CLR directory present) → `unsupported_managed_code`; Mach-O, archives, firmware blobs, DEX, core dumps.
- Size: `RE_MAX_BYTES` 16 MiB default (= the capa cap), validated ≤ 64 MiB (= `STATIC_MAX_BYTES`).

**Ghidra in the sandbox** (decision; final values from the spike)
- **Process per stage:** `analyze` (import + auto-analysis + export + save the project) and `decompile` (re-open the saved project, open the program without saving, decompile the list root chose). Splitting puts the native decompiler, the slowest and least predictable part, in its own process with its own heap, timeout and limits, and lets root choose what to decompile from validated data. Both stages are the same engine and uid, so there is no trust boundary between them (stated); the project dir stays tool-writable (Ghidra writes its lock file), so "read-only" means only "never saved" (RT23). Root writes the priority list to a root-owned `stage/` dir (0755, the file 0444), never into a tool-writable dir.
- **Probe:** `python -I -s -m re_worker.probe <stage>` as uid **10010** (decision: a new tool uid after M8's 10005 / 10006 and M9's 10007 / 10008; 10009 stays unused; phase 1 asserts it is unique across all images; RLIMIT_NPROC is per host uid), from the root-owned read-only input dir. A PEP 578 audit hook (M8 pattern) refuses and counts `socket.*`, `urllib.Request`, `subprocess.Popen` and `os.exec*` / `os.system` / `os.spawn*` events of the Python side, **installed after `pyghidra.start()` returns** (RT1). The JVM's own spawn of the decompiler (through `jspawnhelper`) is a JVM `posix_spawn` (not a Python event); the decompile stage records its children's executables right after each spawn and at the end, expecting only `jspawnhelper` and `/opt/ghidra/.../decompile`. This is **detection, not prevention** (RT15): nothing in the kernel restricts what the tool uid may `execve`; the boundary is the uid, seccomp and rlimits, all inherited by every exec.
- **Sandbox:** `unix_sockets_only=True`, `deny_io_uring=True`; `Rlimits(as_bytes=RE_TOOL_RLIMIT_AS (heap + 3 GiB, spike-tuned), cpu_s = 2 × the stage timeout + 60 (RT3: RLIMIT_CPU sums every JVM thread on 2 CPUs; the wall timeout and the analysis monitor are the real bounds), nproc=256 (spike-measured, below `pids_limit` so root can always fork its kill helper, RT13), nofile=4096, fsize_bytes=1 GiB)`; `oom_score_adj=1000`; container `mem_limit: 4g`, `pids_limit: 512`, `cpus: 2`, read-only rootfs.
- **Decompiler child memory** (RT4): it inherits the JVM's `RLIMIT_AS` (5 GiB > the 4 GiB cgroup), so a pathological function could grow it until the cgroup OOM killer picks the JVM and the whole stage is lost. The decompile stage runs with `RE_DECOMPILE_JVM_HEAP` (1 GiB default) and, after each (re)spawn of the decompiler, lowers the child's `RLIMIT_AS` with `prlimit` (same uid, lowering only) to `RE_DECOMPILER_AS` (1.5 GiB default, spike-tuned); a child that dies marks that function `failed` and `DecompInterface` is re-opened. If the spike shows `prlimit` cannot be applied, the stage records a cgroup OOM as `decompile` `failed` and keeps the functions written so far.
- **Resources measured by root, not by the tool** (RT14): during every stage root polls the container's cgroup `memory.current` (peak per stage) and the `memory.events` `oom_kill` counter; an OOM kill (or the JVM's `ExitOnOutOfMemoryError` exit code 3) becomes `re_out_of_memory` (class `input`). `RUSAGE_CHILDREN` is not used (it gives the largest single process, cumulated over the worker child's life).
- **Disk** (RT5): before the download a free-space check (≥ size + `RE_MAX_WORK_BYTES` + 1 GiB, else `insufficient_disk`); during every stage a root watchdog measures the job dir every 2 s and kills the tool uid above `RE_MAX_WORK_BYTES` (2 GiB default) → `re_work_too_large` (class `input`). `RLIMIT_FSIZE` alone bounds one file, not a project of many files on the Docker VM disk Postgres and MinIO share.
- **JVM options** (`RE_JVM_HEAP` 2 GiB default, ≤ 3 GiB, for `analyze`; `RE_DECOMPILE_JVM_HEAP` for `decompile`; our `launch.properties` carries nothing else, RT1): `-Xmx`, `-XX:+UseSerialGC`, `-XX:ActiveProcessorCount=2`, `-XX:ReservedCodeCacheSize=128m`, `-XX:MaxMetaspaceSize=512m`, `-XX:CompressedClassSpaceSize=256m`, `-XX:MaxDirectMemorySize=256m`, `-Xss1m`, `-XX:-UsePerfData`, `-XX:+DisableAttachMechanism`, `-XX:+ExitOnOutOfMemoryError`, `-XX:ErrorFile=<out>/hs_err.log`, `-Djava.awt.headless=true`, `-Duser.home=<out>/home`, `-Djava.io.tmpdir=<out>/tmp`; env `MALLOC_ARENA_MAX=2`, `JAVA_HOME`, `GHIDRA_INSTALL_DIR`, `XDG_CONFIG_HOME` / `XDG_CACHE_HOME` = fresh out subdirs; a test asserts that `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS` and `DEBUGINFOD_URLS` are absent (RT19). JIT code is RWX on Linux x86-64, so no W^X / MDWE control applies to the JVM (RT29, stated).
- **Import:** only the sample, only `PeLoader` or `ElfLoader` (chosen by root from the magic; never an opinion-based or filesystem / archive loader); no `.gzf` / `.xml` / project archives ever. **Loader options fail closed** (RT20): the probe enumerates the chosen loader's options and fails the stage `re_parse_failed` if any library-loading, library-search-path or project-library-linking option (12.x names such as "Load Local Libraries From Disk", "Load System Libraries From Disk", "Link Existing Project Libraries" [I], recorded by the spike) is enabled or an unknown option appears.
- **Analysis options** (a frozen dict, names checked against 12.2 in phase 2): "Decompiler Parameter ID" off, "Aggressive Instruction Finder" off, "PDB Universal" / "PDB MSDIA" off (the PE CodeView path is attacker-chosen and is never opened; the spike's strace proves it with a PE whose PDB path is `/etc/passwd`, RT19), DWARF external debug files and debuginfod off (DWARF of the binary's own sections on), "Embedded Media" off; the rest at Ghidra defaults. Analysis timeout `RE_ANALYSIS_TIMEOUT_S` (1 500 s) through a timeout task monitor; a cancelled analysis still exports what exists (`stages[].status = timeout`, `truncated.analysis = true`).
- **Decompiler options** (RT16): a fixed `DecompileOptions` with every comment kind off (PLATE, PRE, POST, EOL, header: RTTI / demangled plate comments carry attacker text); decompiler warnings kept.
- **No network anywhere:** no Ghidra Server URLs, no symbol server, no debuginfod; the `analysis` network is internal; seccomp denies every non-AF_UNIX socket. JDK 25 has no SecurityManager, so Java-side denial rests on seccomp and the network (stated in THREAT_MODEL).

**Outputs** (decision; caps in `ReLimits`)
- **Program:** format, arch, bits, endianness, Ghidra language id, compiler spec, image base, entry, counts, analysis status, engine and versions.
- **Functions** (≤ 20 000): entry (VA) and RVA, name (≤ 255, NUL-free), name source (`export`, `import`, `symbol`, `debug`, `fid_library`, `generated`), size, body ranges (≤ 16 half-open RVA ranges; more → `body_truncated`), thunk / external / library flags, signature (≤ 512), calling convention, instruction count, caller / callee counts.
- **Call edges** (≤ 100 000): caller entry, callee entry, call-site count.
- **Imports** (≤ 10 000) and **import references** (≤ 50 000): library, name or ordinal, thunk / IAT address; per (import, calling function) a count.
- **Strings** (≤ 20 000, ≥ 5 characters, value ≤ 1 KiB) and **string references** (≤ 50 000): address, encoding, value; per (string, referencing function) a count.
- **Decompiled functions:** `full` decompiles at most `RE_MAX_DECOMPILED` (300 default, ≤ 2 000) functions, the optional requested `decompile_addresses` (≤ 64) first (RT10: there is no separate `targeted` profile; it would re-run the whole analysis anyway). Each code text ≤ 64 KiB (cut at a line boundary with a `/* [cyberlab: truncated n bytes] */` marker), total ≤ 32 MiB per job; per-function timeout `RE_DECOMPILE_TIMEOUT_S` (30 s); status `ok | timeout | failed | truncated | skipped_budget`; the code's sha256 and line count. `code_kind` is `pseudo_c` (Ghidra) or `disasm` (the no-go fallback / radare2, bounded to 400 instructions).
- **Decompile priority** (root, deterministic, from validated records): requested addresses → the entry point and exports → functions containing a capa RVA of the source job → functions calling an import of an M3 suspicious API set → functions referencing a string that yields an IOC → the rest by size (descending, then entry), skipping thunks, externals and FID library functions. The rank is stored, so the UI can say why a function was or was not decompiled; "Decompile this function" creates a new `full` job with that address first (it re-analyses the sample: minutes; the old job page links to the newer RE job of the same sample).
- **Findings** (phase 5, heuristics capped at `medium`, no verdict words): `heuristic:re_api_set_function@1` (an M3 suspicious API set fires **within one function**: every group of one of its `any_of` combinations has at least one API called from that function, directly or through a thunk, with the M3 `string:run_key` pseudo-API meaning "the function references a Run-key string"; the sets come from `cyberlab_worker.apisets`, lifted from M3 in phase 1, RT7; localizes the M3 file-level finding), `heuristic:re_runtime_api_resolution@1` (a function calling `GetProcAddress` / `dlsym` and referencing ≥ 3 strings that are API names), `heuristic:re_network_string_function@1` (a function referencing a URL / IP string and calling a network API; `low`). Each finding cites its function (entry address in `attributes.function_entry`).
- **IOCs:** URLs, domains, IPs from strings **referenced by code** (shared extractor `cyberlab_worker.iocs`), with the referencing function in the context.

**Storage of large outputs** (decision)
- Postgres rows with hard caps, as for every analyzer (TOAST compresses `re_decompilations.code`); the whole `re.v1` result object also stays in MinIO like other result objects. Worst case per job: 32 MiB code + ≈ 40 MiB of other rows; the result stream ≤ 256 MiB compressed; the RE ingest passes its own framing bounds to `check_framing` (`RE_MAX_RESULT_DECOMPRESSED_BYTES` 768 MiB, lines = sum of caps + 3; a test proves a stream at every cap fits, the M8 RT9 lesson).
- Decompiled code is never copied into findings, reports, the M7 search index or the timeline. It reaches the AI only through `explain_function` (capped, transformed).
- Retention: the bulk `re_*` tables join `retention/select.py:BULK_TABLES`.

**Linking to capa** (decision; phase 6)
- `static.v1` gains, **additively**: `CapabilityRecord.locations: list[Address]` (absolute addresses only, ≤ 32, default `[]`) and `StaticResultHeader.capa_base_address: Address | None = None`. Old streams stay valid. `Strict` refuses unknown fields, so the **api / ingest image is rebuilt before the static image** (an old ingest refuses a stream with `locations`, RT18); static jobs from before M10 have no locations, and the UI says "re-run static analysis to link capabilities".
- Read model (RT6): `CapabilityOut` is **unchanged** (it is also the static JSON report's item type); the capabilities route returns `CapabilityLinkedOut(CapabilityOut)` with `locations` and `functions`; the static report and the M6 snapshot stay byte-identical (golden tests).
- Migration: `malware_capabilities.locations` (jsonb array of decimal strings, ≤ 32, checked) and `malware_samples.capa_base_address` (`NUMERIC(20,0)` NULL).
- Join (RE ingest, trusted; RT8): both sides are normalized to **file virtual addresses**: `file_va = va − (engine_base − preferred_base)`, where `preferred_base` is the file's own base (PE `ImageBase`; ELF lowest `PT_LOAD` `p_vaddr`, page-aligned), taken from the M3 facts and recorded in `re_programs`. A capability links to the function whose body ranges contain its file VA (`re_function_capabilities`). capa (vivisect) and Ghidra may describe their bases differently for ELF EXEC and DYN [I], so a real capa + real Ghidra check on the PE `injector` and the ELF `elf_net` builds (PIE and non-PIE) runs in phase 12; hand-made join tests alone prove nothing about the engines.

**AI: `explain_function`** (decision; phase 9)
- A new requestable, targeted task (`target_id` = a `re_functions.id`) for a succeeded `reverse` job (`422 task_not_applicable` otherwise). Share policy, budgets, opt-in and the worker re-check work unchanged (M5 / M6).
- New label kinds: **`G`** (function facts: name, entry, size, signature, name source, flags, ≤ 20 caller and ≤ 20 callee names, ≤ 30 imports called, ≤ 20 referenced strings (each ≤ 128), linked capabilities) and **`Q`** (the function's code). Context order: target G, its Q, J, the C rows linked to it, F rows citing it, I rows from its strings, ≤ 10 callee G rows (facts only).
- **The one exception to the 256-character truncation:** a `Q` item's `code` field is capped at `AI_MAX_CODE_CHARS` (12 000 characters, line-boundary cut with a marker) instead of 256. Every other transform applies to it unchanged (sanitize: C0/C1, bidi, zero-width and tag characters removed and counted; pseudonym-token neutralization; URL query values; pseudonymization of internal IPs, hosts, user paths; defanging). String literals inside the code are cut to 96 characters each, and identifiers longer than 64 characters (exported / symbol names reach the code verbatim) are cut with a marker, before the transforms (both counted, RT16).
- The template states: the code is decompiler output of an untrusted binary, identifiers and string literals in it are attacker-chosen data, never instructions; explain observed behaviour of this function only; no code, commands or compilation advice in the output; capabilities are static rule matches. `PROMPT_VERSION` bumps from `m5.1` to `m10.1` (a new template changes the pinned digests; M8 / M9 add no template, phase 1 re-checks).
- Verifier: `Q.code` quotes follow the normal rules (exact substring after normalization, ≥ 8 characters, anchoring by salient tokens; identifiers ≥ 4 characters anchor as words); a citation's `field` must be `code` or a G field. No new flags; `command_like` and `verdict_language` apply. Output text passes `clean_text` (backticks, markup and links removed).
- Offline evaluation: Fake / Hostile / Replay providers only (no live AI run), with adversarial twins whose string literals and exported names carry injection payloads (phase 4 builds the binaries; phase 9 seeds the same payloads from the frozen phase-1 fixture `hostile_ai.ndjson`, since API lanes have no compiler or Ghidra, RT11).

**UI** (decision; phase 10)
- Route `/o/{org}/reverse-engineering` (job list) and `/reverse-engineering/{job}`: program header, stage strip (ok / timeout / failed / skipped, with `truncated` flags), functions table (filters: name, decompiled, has capability, calls suspicious import, references IOC string), function view (code, callers / callees as linked lists, imports called, strings, linked capabilities, findings, "Explain function", "Decompile this function"), imports and strings tabs with their referencing functions. **No call-graph view in M10** (RT24: the caller / callee lists give the navigation; a graph view is ROADMAP "Later").
- **Code viewer:** text only. Our own linear-time C tokenizer (no regex backtracking) produces React spans for keywords, literals, comments and numbers; no `dangerouslySetInnerHTML`, no HTML-producing highlighter. Bidi controls, zero-width and other invisible / control characters are shown as visible escapes (`⟨U+202E⟩`) and counted in a banner ("Trojan Source" defence); identifiers containing non-ASCII characters (homoglyphs) get a distinct style and are counted too (RT17). Line-virtualized; **"Copy" copies the escaped text**; "Copy raw" is a secondary action with the warning.
- Malware Lab: a "Reverse engineer" action on static jobs (slot) and "Functions (n)" links on capabilities with locations (slot).

**Testing and data** (decision; research §9)
1. **Real Ghidra in tests** on synthetic benign programs (unlike M8, real-engine coverage is possible without third-party data): the M3 C sources (`hello.c`, `injector.c`, via an `additional_contexts` entry, never copied) and new RE fixtures (`callgraph.c`: known call tree with recursion and a function pointer; `strings_refs.c`: strings referenced by known functions, including a planted prompt-injection literal; `imports_use.c`: known import usage per function, with an inert `GetProcAddress` resolver), plus a generated large program (`bulk_gen.c`, ≈ 5 000 generated functions with calls and switch tables, `-O2`, several MiB: the latency / RSS worst case, since random code bytes stop Ghidra's flow quickly, RT21), compiled at test time with mingw-w64 (PE x86 / x64) and gcc (ELF x64, PIE and non-PIE) in the dev image, each **unstripped and stripped**. Ground truth comes from the unstripped build's symbol table (`nm`) and the linker map. Nothing is committed as a binary; nothing is ever run.
2. **Pure-Python PE / ELF builders** (the M3 `samples/{pe,elf}.py`, imported by path) for structural edge cases and fuzz seeds.
3. **Replay engine** (`RE_ENGINE=replay`, refused unless `TEST_PROFILE=1`, labelled `engine: replay` in every header) feeds hand-written stage outputs through the real normalizer, priority, detections and ingest in lanes that must not start a JVM.
4. **Metrics:** function-recovery precision / recall on the stripped builds, call-edge recall, string-reference recall, import-usage recall, decompile success rate, RE-heuristic precision / recall on the scenario set, latency (p50 / p95) and peak container memory per stage (cgroup, RT14), all with the synthetic caveat.
5. **No real malware, no committed binaries, no downloads at test time** (`requirement.txt` §14).

### Data model (migration **head + 1 after M9, expected `0018`**; the M4–M9 conventions: FORCE RLS on every tenant table, composite same-org FKs, S/I grants plus per-column UPDATE, named checks with `octet_length` caps, no DELETE grant to the app role)

| Table / change | Scope / grants | Notes |
|---|---|---|
| `analyzer` enum | existing | `ADD VALUE 'reverse'` (autocommit block, like 0006) |
| `analysis_jobs.profile` checks | existing | gains `reverse` ∈ (`quick`, `full`) (RT10) |
| `analysis_jobs.source_job_id` | existing table, write-once | uuid, composite same-org FK to `analysis_jobs`; NOT NULL iff analyzer = reverse; the source must be a static job (trigger) |
| `analysis_jobs.re_params` | write-once | jsonb ≤ 2 KiB (`decompile_addresses` 0–64, decimal strings; non-empty only for `full`); NOT NULL iff analyzer = reverse |
| `job_outcomes` kind check | existing | gains `reverse` |
| `malware_capabilities.locations` | existing (M3) | jsonb array ≤ 32 decimal strings, default `[]`, checked |
| `malware_samples.capa_base_address` | existing (M3) | `NUMERIC(20,0)` NULL |
| `re_programs` | tenant; app S/I | PK `job_id`; `format`, `arch`, `bits`, `endianness`, `language_id` ≤ 64, `compiler_spec` ≤ 32, `image_base`, `preferred_base` (RT8), `entry`, `peak_memory_bytes` NULL (RT14), `engine` (`ghidra`/`radare2`/`replay`), `engine_version` ≤ 32, `code_kind`, `stages` jsonb ≤ 8 KiB, `counts` jsonb ≤ 4 KiB, `truncated` jsonb ≤ 2 KiB |
| `re_functions` | tenant; app S/I; retention DELETE | `id`, `organization_id`, `job_id` (all bulk RE tables have these three, M8 RT23), `entry`, `rva`, `name` ≤ 255, `name_source`, `size`, `body` jsonb ≤ 2 KiB, `is_thunk`, `is_external`, `is_library`, `signature` ≤ 512, `calling_convention` ≤ 32, `instructions`, `callers`, `callees`, `decompile_status`, `priority_rank` NULL; unique (`job_id`, `entry`); index (`job_id`, `name`), (`job_id`, `priority_rank`) |
| `re_call_edges` | tenant; app S/I; retention DELETE | `caller_entry`, `callee_entry`, `sites`; unique (`job_id`, `caller_entry`, `callee_entry`); index (`job_id`, `callee_entry`) |
| `re_imports` | tenant; app S/I; retention DELETE | `library` ≤ 128, `name` ≤ 255 NULL, `ordinal` NULL, `address` NULL |
| `re_import_refs` | tenant; app S/I; retention DELETE | `import_id` (same-org FK), `function_entry`, `count`; index (`job_id`, `function_entry`) |
| `re_strings` | tenant; app S/I; retention DELETE | `address`, `encoding`, `value` ≤ 1 024, `length` |
| `re_string_refs` | tenant; app S/I; retention DELETE | `string_id` (same-org FK), `function_entry`, `count`; index (`job_id`, `function_entry`) |
| `re_decompilations` | tenant; app S/I; retention DELETE | `function_entry`, `status`, `code_kind`, `code` ≤ 65 536 octets NULL, `lines`, `code_sha256`, `truncated`; unique (`job_id`, `function_entry`) |
| `re_function_capabilities` | tenant; app S/I; retention DELETE | `function_entry`, `capability_id` (same-org FK to `malware_capabilities`), `file_va` (RT8) |
| retention grants | — | DELETE to `cyberlab_retention` on the nine bulk RE tables; never on `re_programs` |

Addresses are `NUMERIC(20,0)` (the M3 rule). Findings and IOCs use the shared `analysis_findings` / `iocs`. Job summary: `analysis_jobs.summary` (≤ 32 KiB).

## Red-team changes (2026-11-07)

**Reviewers and sources.** Four hostile reviewers (security, reliability, product, scope / parallelism) checked this plan and the research report against the code:
- worker kit `packages/py-worker-kit/src/cyberlab_worker/{sandbox,seccomp}.py` (`_child_setup`: `RLIMIT_CPU` = the wall timeout unless set, `Rlimits`, `unix_only` allowlist over `socket` / `socketpair` only, allow-by-default filter, kill-by-uid helper that forks);
- py-jobs `base.py` (`Strict`: `extra="forbid"`), `static.py` (`CapabilityRecord`, `StaticResultHeader`, `PeInfo` / `ElfInfo`);
- the static worker: `engines/capa.py`, `probe/reduce.py` (capa reducer, 64 MiB document cap), `analyzer.py` (`CAPA_MAX_BYTES` 16 MiB), `detections/apis.py` (`ApiSet{groups, any_of}`), `celery_app.py` (acks early), `pyproject.toml` / `uv.lock` (flare-capa 10.0.0);
- api `analysis/{dispatch,service}.py` (presign TTLs, `auto_choice`), `core/config.py` (active caps, result bounds), `static_analysis/{models,schemas,report,stream}.py` (`CapabilityOut` inside `ReportCapabilities`), `ai/context/{transform,estimate,fields,select}.py`, `ai/contracts.py` (`RefKind`), `ai/prompt.py` (`m5.1`), `reports/citations.py`, alembic `versions/` (head `0015_m7_hold_sync`);
- `docker-compose.yml` (worker anchors, `mem_limit`s, ingest worker), `scripts/lane-test.sh`;
- the M8, M9 and M11 plans (tool uids 10005–10008; migrations 0016 / 0017 / 0019; no new AI task in M8 / M9; lane 9 created by M9);
- upstream `pyghidra/launcher.py` (Ghidra master: `LaunchSupport` via `subprocess.check_output(..., shell=True)`, `java -version`, `launch.properties` `VMARGS` merged, plugin install with a temp-dir lock). Everything else about the JVM, Ghidra option names and radare2 output fields is marked [I] for the spike / engine smoke.

No container was run, nothing was downloaded beyond documentation, and no code was touched.

**Parent decisions encoded:** none beyond the brief (no real malware, no third-party binaries, offline AI evaluation only).

**Result:** 32 findings: 2 High, 10 Medium, 20 Low. 24 were accepted and applied, 8 rejected. Seed questions: Q1 → RT3 / RT4 / RT5 / RT13 / RT14 / RT22; Q2 → RT1 / RT15 / RT19; Q3 → RT19 / RT20; Q4 → RT26; Q5 → RT11 / RT16; Q6 → RT17; Q7 → RT6 / RT8 / RT18; Q8 → RT2 / RT5 / RT21 / RT22; Q9 → RT9 / RT10 / RT24 / RT27 / RT28; Q10 → no finding (phase 11's notice scope is correct; trimming is stated as a modification).

| ID | Finding (failure scenario) | Severity | Disposition |
|---|---|---|---|
| RT1 | **The PyGhidra launcher is not the "fixed vmargs, no subprocess" process the plan assumes.** `start()` runs `LaunchSupport` with `subprocess.check_output(..., shell=True)` and `java -version` to find the JDK, merges `support/launch.properties` `VMARGS` into the JVM arguments (a second GC flag aborts the JVM; others silently change our list), and may install extension plugins with a temp-dir lock. An audit hook installed "after the imports" refuses those subprocesses: the JVM never starts. | High | Accepted → hook installed after `pyghidra.start()` returns, before the sample is opened; the pinned JDK path passed so discovery is skipped where the launcher allows it (else the root-controlled helper runs happen before the hook and are recorded); our own root-owned `launch.properties`; plugin install asserted empty; the effective `getInputArguments()` compared by root (plan Engine choice, Ghidra in the sandbox; phases 1, 2). |
| RT2 | **"One active RE job" does not bound host RAM.** Analyzer caps add up to 16 GiB (pcap 2, static 3, report 1, memory 3, disk 3, RE 4) on an 8–12 GB Docker VM; a memory job, a disk job and an RE job running together exhaust the VM and the OOM killer ends jobs (or Postgres / MinIO) at random. | High | Accepted → `ANALYSIS_HEAVY_MAX_ACTIVE` (default 1) counts active memory, disk and reverse jobs platform-wide and replaces `RE_MAX_ACTIVE_TOTAL`; refusal `429 too_many_active_jobs` with `reason: heavy_analysis_busy` and no detail of another org's job; DEPLOYMENT gives the sizing to raise it; the "queue position" UI claim dropped (plan Architecture, Frozen interfaces 8; phases 1, 7, 10, 11). |
| RT3 | **`RLIMIT_CPU` defaults to the wall timeout and counts every JVM thread.** JIT, GC and the analysis pool on 2 CPUs burn CPU faster than wall time; SIGXCPU kills the JVM before the analysis monitor fires, so nothing is exported and the job fails. | Medium | Accepted → `cpu_s = 2 × stage timeout + 60` set explicitly; the wall timeout and the monitor stay the real bounds; a unit test on the computed `Rlimits` (plan Ghidra in the sandbox; phase 2). |
| RT4 | **The native decompiler inherits `RLIMIT_AS` = heap + 3 GiB (above the 4 GiB cgroup).** A pathological function grows it until the cgroup OOM killer picks the JVM (both at `oom_score_adj` 1000): the whole decompile stage is lost instead of one function. | Medium | Accepted → `RE_DECOMPILE_JVM_HEAP` 1 GiB; the probe lowers the child's `RLIMIT_AS` with `prlimit` to `RE_DECOMPILER_AS` (1.5 GiB) after each (re)spawn; a dead child fails one function and the interface is reopened; spike-verified, with a recorded fallback (plan Ghidra in the sandbox; phases 1, 2). |
| RT5 | **`insufficient_disk` has no mechanism and `RLIMIT_FSIZE` bounds one file only.** A hostile binary makes Ghidra write a project of many large files on the Docker VM disk that Postgres and MinIO share. | Medium | Accepted → free-space check before the download; a root watchdog over the job dir every 2 s kills the tool uid above `RE_MAX_WORK_BYTES` (2 GiB) → `re_work_too_large` (input) (plan Ghidra in the sandbox, Frozen interfaces 7–8; phases 1, 2). |
| RT6 | **`CapabilityOut` is also the static JSON report's item type.** Adding `locations` / `functions` changes `cyberlab.report.static.v1`, contradicting phase 6's "byte-identical" claim, and would put RE joins in the report path. | Medium | Accepted → `CapabilityOut` unchanged; `CapabilityLinkedOut(CapabilityOut)` with `locations` and `functions` on the capabilities route only; golden tests for the static report and the M6 snapshot (plan Linking to capa, Frozen interfaces 5; phases 1, 6, 8). |
| RT7 | **"One function calls every API of a set" never fires.** M3 sets are groups with `any_of` combinations, A / W variants and the pseudo-API `string:run_key`; a copy with an equality test is brittle (M3's module imports `static_worker.detections.base`). | Medium | Accepted → `ApiSet` / `API_SETS` data lifted to `cyberlab_worker.apisets` in phase 1 (the M8 IOC-extractor precedent), M3 re-exports it; the per-function rule uses the M3 combination semantics, run-key = a referenced Run-key string (plan Outputs, Frozen interfaces; phases 1, 5). |
| RT8 | **`location − base` on both sides agrees only if both bases mean the same thing.** Ghidra rebases ELF PIE (e.g. 0x100000) and vivisect's ELF base semantics are unverified [I]; for ELF EXEC one side may report 0 and the other the lowest segment: zero links, silently. | Medium | Accepted → join on file virtual addresses (`va − (engine_base − preferred_base)`, preferred base from the file: PE `ImageBase`, ELF lowest `PT_LOAD`), `preferred_base` stored; real capa + real Ghidra link checks on PE and ELF PIE / non-PIE builds in phase 12 (plan Linking to capa, Data model; phases 4, 6, 7, 12). |
| RT9 | **r2pipe fights the sandbox design.** It spawns radare2 with `subprocess.Popen` inside the probe (refused by the audit hook), buffers replies until NUL with no size bound, and per-address `axtj @` calls keep a formatting path open. | Medium | Accepted → one non-interactive `radare2 -q -NN -S -2 -i <fixed script from the image>` run under `run_tool`, stdout to a file bounded by `RLIMIT_FSIZE`, references from `aflj` per-function `callrefs` / `datarefs` [I, smoke-checked], reduced by a probe as the tool uid; r2pipe dropped (plan Engine choice; phases 1, 3). |
| RT10 | **`targeted` is a full re-analysis in disguise.** Without a kept project, decompiling one function re-imports and re-analyses for minutes and creates a second job holding only a few decompilations; the analyst then has two partial views. | Medium | Accepted → profile `targeted` cut; `full` takes optional `decompile_addresses` (≤ 64) as priority class 1; "Decompile this function" creates a new `full` job with that address first; the old job links to the newer one (plan Outputs, Data model, Frozen interfaces; phases 1, 5, 7, 8, 10, 12). |
| RT11 | **Group-B lanes depend on each other's unmerged code.** Phase 4's quality test needs phase 2's runner; phase 9's AI eval needs phase 4's twins, but API lanes have no compiler or Ghidra. | Medium | Accepted → phase 4's lane does sources, builds, truth and unit tests; `test_recovery_quality.py` runs after the group-B merge as a parent heavy step; phase 1 adds the `hostile_ai.ndjson` fixture with the twin payloads for phase 9 (plan Frozen interfaces 3, Group B merge; phases 1, 4, 9). |
| RT12 | Hide decompiled code from non-admin members. | Medium | Rejected → needs per-field RBAC beyond the M1 org model; residual in THREAT_MODEL. |
| RT13 | **`nproc` 512 equals `pids_limit` 512.** A JVM thread storm fills the container's pids, and root can no longer fork its kill helper. | Low | Accepted → `nproc` 256 (spike-measured), below `pids_limit` (plan Ghidra in the sandbox; phase 2). |
| RT14 | **`RUSAGE_CHILDREN` measures the wrong thing.** It is the largest single process, cumulated over the worker child's life; neither per stage nor JVM + decompiler. OOM kills surface as anonymous `ToolFailed`. | Low | Accepted → root polls cgroup `memory.current` per stage and `memory.events` `oom_kill`; OOM (or JVM exit code 3) → `re_out_of_memory` (input); `re_programs.peak_memory_bytes` (plan Ghidra in the sandbox, Data model; phases 1, 2, 12). |
| RT15 | **The "only child is the decompiler" check is detection with a race.** Children are read at the end (gone after `dispose`), the JDK spawns through `jspawnhelper`, and nothing restricts `execve` for the uid. | Low | Accepted → children recorded after each spawn and at the end, `jspawnhelper` expected; THREAT_MODEL and DoD call it detection; the boundary is the inherited uid / seccomp / rlimits (plan Probe, Definition of done; phases 2, 11, 12). |
| RT16 | **Attacker text bypasses the literal cut.** Exported / symbol names (≤ 255 characters) appear verbatim in the code, and RTTI / demangled plate comments are printed by default options. | Low | Accepted → `DecompileOptions` with every comment kind off; identifiers > 64 characters cut in `Q.code` (counted) (plan Ghidra in the sandbox, AI; phases 2, 9). |
| RT17 | **"Copy" hands raw bidi text to an IDE or shell; homoglyph identifiers are invisible.** | Low | Accepted → "Copy" copies the escaped text, "Copy raw" is secondary with a warning; non-ASCII identifiers styled and counted (plan UI; phase 10). |
| RT18 | **Mixed images during rollout.** `Strict` forbids extra fields, so a new static worker's `locations` are refused by an old ingest. | Low | Accepted → api / ingest image rebuilt before the static image; both directions tested (plan Linking to capa, Group B merge; phase 6). |
| RT19 | **Cheap JVM and input hardening is missing.** The attach listener, `JAVA_TOOL_OPTIONS` / `JDK_JAVA_OPTIONS` / `_JAVA_OPTIONS` / `DEBUGINFOD_URLS`, and the attacker-chosen PE CodeView PDB path are not pinned down. | Low | Accepted → `-XX:+DisableAttachMechanism`; an env test asserts those variables are absent; the spike's strace proves a PE with PDB path `/etc/passwd` opens nothing outside the out dir (plan Ghidra in the sandbox; phase 2). |
| RT20 | **Library-loading options are named, not enforced.** 12.x option names changed across versions [I]; a renamed option would silently stay at its default. | Low | Accepted → the probe enumerates the chosen loader's options and fails closed on any enabled library / search-path / project-link option or an unknown option (plan Import; phase 2). |
| RT21 | **Random code bytes are not the analysis worst case** (flow stops at the first bad instruction). | Low | Accepted → `bulk_gen.c` (≈ 5 000 generated functions, switch tables, `-O2`) is the latency / RSS case for phase 4 and phase 12; the random-code PE stays a robustness case (plan Testing; phases 2, 4, 12). |
| RT22 | **The test tmpfs `/work` (768 MiB) counts against the 4 GiB cgroup.** Large fuzz / bulk cases then OOM inside the test container. | Low | Accepted → `re-worker-test` `/work` is an anonymous per-container volume (disk-backed, removed with `--rm`, still isolated per container) (plan Frozen interfaces 9; phase 1). |
| RT23 | **Root's hand-off file and the "read-only" project.** The priority list must not be written into a tool-writable dir; the decompile stage still writes Ghidra's lock file. | Low | Accepted → root writes `stage/decompile_list.json` in a root-owned dir; wording "opened without saving" (plan Process per stage; phase 2). |
| RT24 | **The call-graph view is YAGNI.** A layered SVG layout, a BFS route and its tests duplicate the caller / callee lists for a learning-grade platform. | Low | Accepted → route, `graph.py` and `call-graph.tsx` cut; ROADMAP "Later" (plan UI, Frozen interfaces 5; phases 8, 10, 12). |
| RT25 | **Allocation text is stale.** M9's uids (10007 / 10008) are unnamed, lane 9 already exists after M9, `PROMPT_VERSION` is `m5.1` with no M8 / M9 bump. | Low | Accepted → stated: uid 10010 (10009 unused), migration `0018` (M11 expects `0019`), lane 9 reused, `m10.1` (plan What exists, Dependencies; phase 1). |
| RT26 | Merge `analyze` and `decompile` into one JVM to save 10–15 s. | Low | Rejected → the native decompiler gets its own heap, limits and timeout (RT4 needs that), and root picks the list from validated data. |
| RT27 | Cut radare2 entirely. | Low | Rejected → named in `requirement.txt`, the no-go fallback, already optional and cut first; RT9 simplifies it. |
| RT28 | Cut `explain_function`. | Low | Rejected → `requirement.txt` §9 and the main AI value of RE; offline evaluation only. |
| RT29 | W^X / `PR_SET_MDWE` for the JVM. | Low | Rejected → the JIT code cache is RWX on Linux x86-64 and `-Xint` is far too slow; stated in THREAT_MODEL. |
| RT30 | Queue heavy jobs instead of refusing with 429. | Low | Rejected for M10 → needs a cross-queue scheduler; 429 + retry suffices on one node; ROADMAP "Later". |
| RT31 | Run radare2 in its own container. | Low | Rejected → the same uid sandbox contains it; another image and service for a cuttable profile. |
| RT32 | Keep the Ghidra project between jobs to make single-function decompiles cheap. | Low | Rejected → disk on the shared VM and a tool-written project is untrusted state; RT10 instead. |

Seed questions given to the reviewers (kept for traceability):

1. Can a hostile PE / ELF make the JVM, the Ghidra loader or the native decompiler escape its limits: RSS above the cgroup through mmap or direct buffers, a hang the timeout monitor does not cancel, gigabytes of exported rows before the caps, a fork beyond the decompiler, a write outside the out dir (project, logs, `hs_err`)?
2. Is AF_UNIX-only seccomp plus the internal network really enough for a JVM without a SecurityManager (JNI, `ProcessBuilder`, the decompiler child, Ghidra's symbol-server and debuginfod code paths)? Does the JVM even start with inet sockets denied?
3. Is "PeLoader / ElfLoader only, no library loading" enforceable through `program_loader()`, or can a crafted file still pull Ghidra into a filesystem / archive loader or read other files?
4. Two JVM stages per job (≈ 10–15 s extra start-up): worth it, or should analysis and decompilation share one process?
5. Can decompiled code, function names or string literals inject into the AI context beyond what the M5 transforms catch (12 000-character `Q` items, identifiers that look like labels, fake delimiters, comment-like text, Trojan Source)? Is the `Q` exception to the 256-character cap safe?
6. Can the code viewer be abused: tokenizer ReDoS, huge lines, bidi tricks that make code read differently, copy-paste of attacker text into a shell or IDE?
7. Is the additive `static.v1` change safe (old streams, mixed image versions during rollout, the M6 report snapshot, citations of capabilities)? Is the RVA join correct for PE, ELF PIE and ELF non-PIE?
8. Do 4 GiB for the RE worker, the 1.2–1.9 GB image and Ghidra projects of hundreds of MiB hold on the 8–12 GB Docker Desktop host alongside the stack? Is one active RE job globally acceptable?
9. Scope: is the radare2 `quick` profile, the `targeted` profile, the call-graph view or any heuristic YAGNI for a learning-grade single-node platform?
10. License: are the Ghidra GPL native helpers, JDK (GPLv2 + CPE) and radare2 (LGPL-3.0) obligations correctly scoped to image redistribution, and is trimming the Ghidra install a "modification" that needs a notice?

## Phases

| Phase | Name | Group | Depends on | Status |
|-------|------|-------|------------|--------|
| 1 | [Foundation contracts migration and re worker skeleton](./phase-01-foundation-contracts-migration-and-re-worker-skeleton.md) | A | — | Pending |
| 2 | [Ghidra sandbox spike and headless engine runner](./phase-02-ghidra-sandbox-spike-and-headless-engine-runner.md) | spike: A′ (parallel with phase 1, heavy, alone); rest: B (2a, lane 2, `--heavy` for engine runs) | spike: —; rest: 1 | Pending |
| 3 | [Radare2 quick profile engine](./phase-03-radare2-quick-profile-engine.md) | B (2b, lane 3; **optional, cut first**) | 1 | Pending |
| 4 | [Synthetic re sample set ground truth and engine smoke](./phase-04-synthetic-re-sample-set-ground-truth-and-engine-smoke.md) | B (2c, lane 4, no JVM; the quality run after the group-B merge, heavy, parent, RT11) | 1 | Pending |
| 5 | [Re detections decompile priority and scenario evaluation](./phase-05-re-detections-decompile-priority-and-scenario-evaluation.md) | B (2d, lane 5) | 1 | Pending |
| 6 | [Static capa locations for function linking](./phase-06-static-capa-locations-for-function-linking.md) | B (2e, static image lane, `--heavy` once) | 1 | Pending |
| 7 | [Re dispatch and trusted ingest](./phase-07-re-dispatch-and-trusted-ingest.md) | B (2f, lane 6) | 1 | Pending |
| 8 | [Re read api](./phase-08-re-read-api.md) | B (2g, lane 7) | 1 | Pending |
| 9 | [Ai explain function reports and retention integration](./phase-09-ai-explain-function-reports-and-retention-integration.md) | B (2h, lane 8) | 1 | Pending |
| 10 | [Reverse engineering frontend](./phase-10-reverse-engineering-frontend.md) | B (2i, web only) | 1 (frozen contracts) | Pending |
| 11 | [Docs threat model and license notices](./phase-11-docs-threat-model-and-license-notices.md) | C | B merged | Pending |
| 12 | [Hardening e2e fuzz metric and gate](./phase-12-hardening-e2e-fuzz-metric-and-gate.md) | D | all | Pending |

Effort (after the red team): 32 + 36 (8 spike + 28) + 12 + 12 + 10 + 8 + 16 + 10 + 16 + 15 + 8 + 14 = **189 h** (phase 3 optional: 177 h without it; RT1 / RT4 / RT5 / RT14 add runner work, RT10 / RT24 remove the `targeted` profile and the call-graph view). Critical path: max(phase 1, spike) → phase 2 rest (28 h) → the merged quality run (≈ 2 h, RT11) → 11 → 12, about 32 + 28 + 2 + 8 + 14 = **84 h** of wall time with nine group-B agents. At most three lane slots at once; a `--heavy` lane takes two, and every JVM run is `--heavy`.

## Dependencies and parallelism

**Cross-plan:** blocked by `261107-1200-cyberlab-m9-disk-forensics` (itself after M8). Its gate must be green and merged first. Phase 1 then:
- confirms the alembic head and takes head + 1;
- confirms the tool uids used by M8 / M9 (expected 10005 / 10006 and 10007 / 10008) and that 10010 is free (else the next free one, recorded);
- confirms the M8 / M9 versions of the files it edits: `analysis/{models,analyzers,service,dispatch}.py`, `workers/{celery_app,tasks,ingest,reaper}.py`, `ops/error_classes.py`, `retention/select.py`, `ai/{contracts,prompt}.py`, `ai/context/{fields,select,builder}.py`, compose, `infra/redis-broker/entrypoint.sh`, `scripts/lane-test.sh`, `lib/{nav,audit-actions,http-errors,analysis,ai}.ts`, the analyzer-sweep files and `test_analyzer_exhaustive.py`;
- confirms `PROMPT_VERSION` after M8 / M9 (expected still `m5.1`) and picks `m10.1`;
- creates `feat/m10-reverse-engineering` from the M9 merge.

**Group A: phase 1, one agent; frozen when committed.** Only the parent changes frozen files afterwards; a change request goes to the parent, which decides and broadcasts it. **Group A′: the phase-2 spike**, in worktree `..\cyber-wt\m10-spike` from the M9 merge, in parallel with phase 1; its go / no-go is recorded before group B starts.

**Frozen interfaces** (phase 1 notes record the exact signatures):
1. **Contract `packages/py-jobs/src/cyberlab_jobs/reverse.py`**, exported from `__init__.py`:
   - `RE_SCHEMA = "re.v1"`; `ReProfile` (`quick`, `full`; RT10); `ReEngine` (`ghidra`, `radare2`, `replay`); `CodeKind` (`pseudo_c`, `disasm`); `ReStage` (`analyze`, `decompile`, `r2`); `NameSource`; `DecompileStatus`;
   - `ReLimits` (the caps above, `max_work_bytes` (RT5); `decompile_timeout_s < tool_timeout_s < timeout_s`);
   - `ReJobV1` {`job_id`, `organization_id`, `evidence_id`, `source_job_id`, `expected_sha256`, `size_bytes`, `evidence_url`, `result_post`, `ingest_token`, `profile`, `file_format` (`pe`/`elf`), `decompile_addresses` (0–64, `full` only), `capa_file_vas` (≤ 512, RT8), `limits`};
   - result lines: `ReResultHeader` {`job_id`, `profile`, `engine`, `code_kind`, `tool_versions`, `stages[]` {`stage`, `status`, `duration_ms`, `error_code?`} (peak memory is measured by root from the cgroup and added by root, RT14), `audit` {event counts}, `jvm_args` (the effective list, RT1), `engine_errors`, `truncated`}; `ReProgramRecord`; `ReFunctionRecord`; `ReCallEdgeRecord`; `ReImportRecord`; `ReImportRefRecord`; `ReStringRecord`; `ReStringRefRecord`; `ReDecompiledRecord`; the shared `FindingRecord`, `IocRecord`, `ResultTrailer`;
   - framing: header first, program second, trailer last, the M3 value bounds; diagnostic stream (`unsupported_architecture`, `unsupported_managed_code`): header + program + trailer.

   Task `RE_ANALYZE = "reverse.analyze"`, `Queues.reverse`.

   **Shared API sets** (RT7): `packages/py-worker-kit/src/cyberlab_worker/apisets.py` holds the M3 `ApiSet` / `API_SETS` data (no finding logic); `static_worker/detections/apis.py` imports it with unchanged behaviour (M3 tests unchanged); phase 5 consumes it.
2. **`static.v1` additive fields** (`cyberlab_jobs/static.py`): `CapabilityRecord.locations: list[Address]` (≤ 32, default `[]`), `StaticResultHeader.capa_base_address: Address | None = None`; a test proves every M3 fixture still validates and an old stream ingests.
3. **Fixtures `packages/py-jobs/tests/fixtures/reverse/`** (shared by the API and the worker): `pe_full.ndjson`, `elf_full.ndjson`, `quick.ndjson`, `full_requested.ndjson` (with `decompile_addresses`), `unsupported_arch.ndjson`, `hostile_ai.ndjson` (the phase-4 twin payloads in names, literals and code, for phase 9, RT11), `hostile/*.ndjson`; round-tripped by `test_reverse_contract.py`.
4. **Migration head + 1** and the models in `app/modules/reverse_engineering/models.py`; `Analyzer.REVERSE`; the M3 columns. Later schema needs go into head + 2, assigned by the parent.
5. **Schemas and 501 stubs** for every new route, then one `pnpm gen:contracts` run:
   - `reverse_engineering/schemas.py`;
   - the analysis request body gains `analyzer: reverse`, the RE profiles, `source_job_id` and `decompile_addresses`;
   - `CapabilityLinkedOut(CapabilityOut)` with `locations` and `functions` (count, from phase 8) for the capabilities route; `CapabilityOut` itself unchanged (RT6);
   - error codes `static_analysis_required` (409), `re_sample_too_large` (413), `unsupported_architecture`, `unsupported_managed_code`, `profile_unavailable` (422), `function_not_found`; `too_many_active_jobs` (429) gains `reason: heavy_analysis_busy` (RT2).

   Routes (under `/api/v1/orgs/{org_id}`):

   | Method and path | Permission | Phase |
   |---|---|---|
   | `GET /analyses/{job}/reverse` (summary) | `evidence.read` | 8 |
   | `GET /analyses/{job}/reverse/functions`, `…/functions/{entry}` | `evidence.read` | 8 |
   | `GET /analyses/{job}/reverse/functions/{entry}/code` | `evidence.read` | 8 |
   | `GET /analyses/{job}/reverse/imports`, `…/strings` | `evidence.read` | 8 |
   | `GET /analyses/{static_job}/capabilities/{id}/functions` | `evidence.read` | 8 |
   | existing `POST /evidence/{id}/analyses` (`analyzer: reverse`) | `evidence.write` | 7 |
   | existing `POST /ai/runs` (`task: explain_function`) | `evidence.write` | 9 |
6. **Cross-phase entry points** (stubs; ownership moves to the named phase, which never changes the signature):
   - `reverse_engineering/dispatch.py: build_re_message(item, source_job, settings) -> ReJobV1` (phase 7);
   - `reverse_engineering/ingest.py: async ingest_re(job, msg, path) -> None` and `async ingest_re_diagnostic(job, msg, path) -> None` (phase 7), called from `workers/ingest.py` by schema version;
   - worker `re_worker/priority.py: rank(view: ReView, job: ReJobV1) -> list[int]` (phase 5; called by phase 2);
   - worker `re_worker/detections/__init__.py: run(view: ReView, limits: ReLimits) -> DetectionOutput` (phase 5; called by phases 2 and 3);
   - worker `re_worker/engines/r2.py: run_quick(ws, job, budget) -> EngineOutput` (phase 3; called by phase 2's pipeline; until then raises `ProfileUnavailable`);
   - worker `re_worker/view.py: ReView` (**implemented** in phase 1: the normalized in-memory view the pipeline builds from validated records, shared by phases 2, 3 and 5);
   - api `ai/context/select.py: select_function_items(session, run, target) -> list[Item]` (phase 9; stub raising `NotImplementedError`).
7. **`ops/error_classes.py`** gains every RE code (**implemented** in phase 1): `unsupported_architecture`, `unsupported_managed_code`, `unsupported_format`, `re_sample_too_large`, `re_out_of_memory` (RT14), `re_work_too_large` (RT5) → input; `re_parse_failed`, `jvm_start_failed` → parse / engine; `analysis_timeout`, `decompile_timeout`, `insufficient_disk` → infra.
8. **Settings** (`core/config.py`): `RE_MAX_BYTES` (≤ 64 MiB), `RE_MAX_RESULT_BYTES`, `RE_MAX_RESULT_DECOMPRESSED_BYTES`, `ANALYSIS_RE_TIMEOUT_S` (3 600), `RE_ANALYSIS_TIMEOUT_S` (1 500), `RE_DECOMPILE_TIMEOUT_S` (30), `RE_MAX_DECOMPILED` (300, ≤ 2 000), `RE_MAX_ACTIVE_PER_ORG` (1), **`ANALYSIS_HEAVY_MAX_ACTIVE`** (1: active memory + disk + reverse jobs platform-wide, replaces `RE_MAX_ACTIVE_TOTAL`, RT2), `RE_QUICK_ENABLED`, `RE_MAX_WORK_BYTES` (2 GiB, RT5), the per-kind caps, `AI_MAX_CODE_CHARS` (12 000). Worker: `RE_JVM_HEAP` (2 GiB), `RE_DECOMPILE_JVM_HEAP` (1 GiB), `RE_DECOMPILER_AS` (1.5 GiB, RT4), `RE_TOOL_RLIMIT_AS`, `RE_ENGINE` (`ghidra`; `replay` refused unless `TEST_PROFILE=1`), `CYBERLAB_TOOL_UID` / `GID` = 10010.
9. **Services** (compose; dev, test and prod):
   - `re-worker`: the `analysis` network, the broker URL only, the `re_work` volume, the M3 isolation keys, `mem_limit: 4g`, `pids_limit: 512`, `cpus: 2`;
   - `re-worker-test`: test profile, `test.` queue prefix, `/work` an anonymous per-container volume (disk-backed, removed with `--rm`; a tmpfs would count against the 4 GiB cgroup, RT22), bind mounts of `re_worker/`, `tests/`, `samples/`, `dataset/` and the two packages (M8 RT6);
   - broker ACL user `reverse`;
   - `scripts/lane-test.sh` accepts `--service re-worker-test` (and `static-worker-test` for phase 6) and lane 9 (`cyberlab_b9_test`, already created by M9; created if missing);
   - `package.json`: `re:metrics` (stub, exit 2).
10. **Worker skeleton** `apps/workers/reverse/`:
    - `Dockerfile` (structure of the static one): `python:3.12-slim-trixie`; a JDK 25 copied from a digest-pinned `eclipse-temurin:25-jdk` stage (JRE if the spike proves it enough); Ghidra 12.2 zip downloaded in a build stage and **verified against the release SHA-256** (a constant), unpacked to `/opt/ghidra`, trimmed by the spike's list, root-owned, read-only; PyGhidra from the bundled `pypkg/dist` wheel and JPype1 from `uv.lock` (hash-pinned); radare2 6.2.6 deb, sha256-pinned, and the fixed script `/opt/re/r2/quick.r2` (root-owned; no r2pipe, RT9); our reviewed `support/launch.properties` replacing Ghidra's (RT1); `finalize_image.py` asserts versions (Ghidra 12.2, PyGhidra, JDK 25, radare2 6.2.6), that `jython` and Ghidra `server/` are absent, writes `versions.json` and copies every license file to `/usr/share/doc/cyberlab-re/`; dev target adds `gcc`, `gcc-mingw-w64-x86-64`, `gcc-mingw-w64-i686`, `binutils` (for `nm` / `strip`) and the M3 C sources through `additional_contexts`;
    - `pyproject.toml`, `uv.lock`;
    - `re_worker/{celery_app,config,view}.py` (implemented);
    - `analyzer.py` (stub: fails `not_implemented`);
    - empty `probe/`, `engines/`, `normalize/`, `detections/`, `samples/`, `dataset/` packages; `tests/conftest.py`;
    - the py-worker-kit isolation tests wired into the image.
11. **Test helpers:** `tests/reverse_helpers.py` (`seed_re_job()` from the fixture, `seed_static_source_job()` with capability locations); `tests/security/idor_cases_reverse.py` with `PENDING_ROUTES`; `test_rls_coverage.py`, `test_append_only.py`, `test_dynamic_gate.py` updated, then frozen.
12. **Web shared:** `lib/nav.ts` (Reverse Engineering live), `lib/audit-actions.ts`, `lib/http-errors.ts` (the codes above), the analyzer badge value `reverse`; the empty slots mounted once: `components/reverse/run-re-analysis.tsx` (Malware Lab job header), `components/reverse/capability-functions-link.tsx` (capability rows in `components/malware/signature-tabs.tsx`), `components/reverse/explain-function-button.tsx` (inside the RE pages only).
13. **Analyzer sweep** (the M8 RT1 pattern, implemented): a `reverse` arm in every analyzer-keyed branch (search href, case ATT&CK sources, timeline title "Reverse engineering", ops kinds and Literals, report citations and redaction, AI service outputs, analysis schemas / service, web `lib/{analysis,correlation,ai}.ts` with route `reverse-engineering/{id}` and labels "RE (quick)" / "RE (full)"); `test_analyzer_exhaustive.py` and `lib/analysis.test.ts` extended.
14. **AI enums** (frozen, implemented as values only): `AiTask.EXPLAIN_FUNCTION` (requestable, targeted), `RefKind` `G` (function) and `Q` (code); the `explain_function` template file exists with its final text from phase 9 left as a stub that the run path refuses (`422 task_not_applicable` until phase 9).

**Group B: phases 2–10, in parallel** (one subagent each, own worktree from the phase-1 commit, file-disjoint). Each phase's tests pass in isolation against the phase-1 stubs, fixtures and frozen schemas. Cross-phase behaviour is tested after the merge (phase 12). Nobody runs `pnpm verify` or the full suite in a lane.

| Phase | Owns (creates or edits; nobody else touches these in group B) |
|---|---|
| 2 (2a) | `apps/workers/reverse/re_worker/{analyzer,pipeline}.py`, `probe/**` except `probe/r2.py` (PyGhidra stages, launcher, audit hook), `engines/{ghidra,replay,workspace,watch}.py` (`watch.py`: disk watchdog and cgroup poller, RT5 / RT14), `normalize/**`, `tests/fixtures/stage_rows/**`, `tests/unit/test_{pipeline,normalize_*,hostile_output,jvm_args,loader_choice,analysis_options,audit_hook,caps,rlimits,watch}.py`, `tests/engine/test_ghidra_smoke.py`, the spike notes in the phase file |
| 3 (2b) | `re_worker/engines/r2.py`, `probe/r2.py` (the reducer), `tests/unit/test_r2_*.py`, `tests/engine/test_r2_smoke.py` (the script file is frozen in phase 1; a change goes through the parent) |
| 4 (2c) | `apps/workers/reverse/samples/**` (C fixtures, `generate.py`, `truth.py`, injection twins), `tests/unit/test_samples.py`, `tests/engine/test_recovery_quality.py` |
| 5 (2d) | `re_worker/priority.py`, `re_worker/detections/**`, `apps/workers/reverse/dataset/**`, `tests/unit/test_{priority,detections_*,dataset_quality,finding_wording}.py` |
| 6 (2e) | `apps/workers/static/static_worker/{probe/reduce.py (capa locations), engines/capa.py, pipeline.py header field}`, `apps/api/app/modules/static_analysis/{ingest,repository,schemas_out}.py` capa-location parts, their tests |
| 7 (2f) | `reverse_engineering/{dispatch,ingest,stream,join}.py`, the RE branches of `analysis/{service,dispatch,analyzers}.py`, `workers/{ingest,reaper}.py`, their tests |
| 8 (2g) | `reverse_engineering/{router,repository,service}.py`, the capability-functions route in `static_analysis/router.py`, `tests/security/idor_cases_reverse.py`, their tests |
| 9 (2h) | `ai/context/select.py` (function selector), `ai/context/fields.py` (G / Q allowlists), `ai/context/transform.py` (the `Q.code` cap and literal cut), `ai/context/c_literals.py` (new, linear literal scanner), `ai/prompts/explain_function.txt`, `ai/prompt.py` (version bump), `ai/verify.py` (G / Q field rules), `ai/service_outputs.py` RE deep links, `reports/{citations,snapshot_sections}.py` RE function rows, `retention/select.py` (`BULK_TABLES`), the AI eval cassettes and seeded twin rows (from `hostile_ai.ndjson`), their tests |
| 10 (2i) | `apps/web/lib/{reverse,c-tokenizer}.ts` (+ tests), `lib/use-re-job.ts`, `components/reverse/**` (the slots included), `app/(app)/o/[orgId]/reverse-engineering/**`; no mount edits |

- **Shared files touched only by phase 1:** `core/config.py`, `app/main.py`, `app/models.py`, `analysis/models.py`, `ops/error_classes.py`, `ai/contracts.py`, `static_worker/detections/apis.py` (the re-export, RT7); `workers/{celery_app,tasks}.py`; compose files, `.env.example`, `package.json`, `infra/redis-broker/entrypoint.sh`, `scripts/lane-test.sh`; `packages/py-jobs/**`, `packages/py-worker-kit/**`, `packages/contracts/**` (generated after phase 1, then after the merge); `apps/workers/reverse/{Dockerfile,pyproject.toml,uv.lock}`, `re_worker/{celery_app,config,view}.py`; `apps/web/lib/{nav,audit-actions,http-errors}.ts`, the analyzer badge, the slot mounts; the analyzer-sweep files; the frozen test files.
- **Group B merge (parent):**
  1. Merge the nine worktrees; any conflict is a plan bug.
  2. Full API suite.
  3. `pnpm gen:contracts` with no drift.
  4. `pnpm --filter web test typecheck`.
  5. Rebuild the RE image once (heavy, alone), then the **api image before the static image** (an old ingest refuses `locations`, RT18); run the RE worker suite with `--heavy`, then phase 4's `test_recovery_quality.py` over the whole sample set (heavy, alone, RT11). Every image that copies py-jobs / py-worker-kit (api, pcap, static, report, memory, disk) was rebuilt once after phase 1, one at a time.
  6. Fix seams in the owning files, one commit per phase.
- **Group C: phase 11** (docs) after the merge. **Group D: phase 12 last**, the only phase allowed to touch other phases' files, and only for gate fixes.
- **One commit per phase.** The stack stays deployable after each: new routes answer 501 until their phase lands; the RE worker fails jobs with `not_implemented`; no RE job is ever created automatically.

### Parallel execution on this host (the M5–M8 lane scheme, `scripts/lane-test.sh`; 4–8 GB free)

1. **One shared infra stack**, started by the parent after the M9 gate: `postgres`, `redis`, `redis-broker`, `minio` (+ init, `db-bootstrap`). Everything else is stopped during group B.
2. **Worktrees** `..\cyber-wt\m10-b{n}` (`-b m10/b{n}` from the phase-1 commit), with `.env` copied in.
3. **Images:** the parent builds `cyberlab/re-worker:dev` once after phase 1 (heavy, alone: a ≈ 570 MB download and a 1.2–1.9 GB image; no C++ toolchain), then the api, static and the other py-jobs images, one at a time. Lanes never build.
   - **Spike (phase 2, A′):** during phase 1, a throwaway image from the spike worktree (the kit + JDK 25 + Ghidra 12.2 + PyGhidra; parent-built, heavy, alone) runs on the mingw samples compiled inside it; no slot is used by anything else while it runs.
4. **Worker lanes** (`--service re-worker-test`, broker db only): phase 2 → lane 2, phase 3 → lane 3, phase 4 → lane 4 (no JVM), phase 5 → lane 5. Every run that starts a JVM adds `--heavy` (two of the three slots); radare2 and pure unit runs take one.
5. **Static lane (phase 6):** `--service static-worker-test` on lane 9 for the probe change; its API ingest tests in lane 9 too (`cyberlab_b9_test`).
6. **API lanes:** phase 7 → lane 6, phase 8 → lane 7, phase 9 → lane 8. Run with `scripts/lane-test.sh <lane> uv run pytest -q -p no:cacheprovider <own paths>`.
7. **Never from a lane:** `up`, `down`, `build`, `restart` or `stop`.
8. **Heavy steps (the parent runs each alone, with only the infra stack up):** the spike image and its runs; the RE image build; phase 4's quality run over the whole sample set (after the group-B merge); phase 12's fuzz-lite and metrics.
9. **Web lane (phase 10):** host `pnpm --filter web test -- <own paths>`, `typecheck`, `lint`. No containers, no slot.
10. **Fallback** when worktrees misbehave on Windows: the M5 fallback (main tree, lane variables in the shell, `python -m compileall` before each run).

## Definition of done

- **Pipeline:** from a succeeded static `full` job on a PE / ELF (x86 / x64, ≤ 16 MiB), an analyst can request `full` (Ghidra; optionally with requested addresses decompiled first), and `quick` when phase 3 shipped; a second heavy analysis (memory, disk or reverse) is refused while one is active. The worker verifies the sha256, runs each stage in the sandbox offline, and posts a `re.v1` stream; the ingest validates it whole and writes it in one transaction; partial runs show per-stage status and `truncated` flags.
- **Outputs:** functions, call edges, imports with their callers, strings with their referencing functions, decompiled pseudo-C for the prioritized functions (caps enforced, truncation marked), capa capabilities linked to functions for static jobs run after M10.
- **Never executed:** no test, path or option runs the sample; the audit hook records no Python network / process event after the JVM start, and the decompile stage's recorded children are only `jspawnhelper` and the decompiler binary (detection, tested; RT15).
- **AI:** `explain_function` produces a verified `ai.v1` output with citations to `G` / `Q` items offline (Fake / Hostile / Replay); the hostile twins' injected literals and names do not change the verdict-free output rules (flags raised where expected, canary never leaked).
- **UI:** the RE pages render code as text with the safe tokenizer; bidi / control characters and non-ASCII identifiers are visible; "Copy" copies the escaped text; Malware Lab links work both ways.
- **Quality:** function-recovery precision / recall, call-edge and xref recall, decompile success rate and RE-heuristic precision / recall on the synthetic set, latency and peak container memory (cgroup), in `plans/reports/re-metric-YYMMDD.md` with the caveat.
- **Security:** every new route in the IDOR enumerator and every new tenant table in RLS coverage; the env check proves the RE worker has only the broker URL and the `analysis` network; fuzz-lite ends cleanly with no surviving tool process; every analyzer-keyed branch has a `reverse` arm.
- **Gate:** `pnpm verify:prod` green (the dynamic-gate test included); the e2e covers request, job page, function view, code viewer, explain (mock provider) and the Malware Lab links.
- **Docs:** `docs/REVERSE_ENGINEERING.md` (new); ARCHITECTURE, THREAT_MODEL (M10), DATABASE, API, AI_ANALYST (`explain_function`, `G` / `Q`), MALWARE_ANALYSIS (capa locations), DEPLOYMENT (image size, RAM, disk), TESTING (metrics), ROADMAP, PRD and README updated; the license notices in the image and in the docs.

## Out of scope

- **Execution of any kind:** debugging, emulation (Ghidra P-code emulator, radare2 ESIL), dynamic analysis (stays gated).
- **Formats and architectures:** ARM / AArch64 / MIPS / PowerPC, .NET / Java / Android bytecode, Mach-O, firmware, kernel modules beyond plain ELF, packed-sample unpacking.
- **Analyst editing:** renaming, retyping, comments or patching in the decompiler (results are read-only; a Ghidra project is never kept or exported), collaborative Ghidra Server, BSim similarity search, Version Tracking / binary diffing.
- **Extraction:** dumping embedded resources or carved files as new evidence.
- **AI extras:** a job-level "summarize RE" task, AI-driven renaming, model tools; live AI runs (no key yet).
- **Search:** RE function names and code in the M7 org-wide search index ("Later").
- **UI extras:** a call-graph view ("Later", RT24); a queue for heavy jobs instead of `429` ("Later", RT30).
- **Never:** downloading any third-party binary or malware corpus for tests; the decompiler running in the API or the ingest worker.

## Open risks

- **Ghidra in the sandbox** (go / no-go): a JVM under AF_UNIX-only seccomp with tight rlimits is unproven here; the spike decides, and the fallback (radare2 only, no pseudo-C) costs the decompilation value. Recorded either way.
- **Host RAM and disk:** a 4 GiB RE worker beside the stack on an 8–12 GB host; heavy steps alone; one active heavy analysis platform-wide (RT2), the disk watchdog (RT5); the image adds 1.2–1.9 GB to Docker Desktop's growing virtual disk; Ghidra projects of hundreds of MiB in `re_work` per job (wiped after each job). DEPLOYMENT states the sizing.
- **Latency and contention:** minutes per sample; while one heavy analysis runs, other analysts (in any org) get `429 heavy_analysis_busy` and retry; the `quick` profile (if shipped) gives fast partial answers. One org can keep the heavy slot busy with sequential jobs (residual, documented).
- **Parser exposure:** Ghidra's native decompiler and demangler and radare2's C parsers parse hostile input: contained (uid, seccomp, rlimits, cgroup, read-only rootfs, no egress, kill-by-uid), not prevented. Updates mean rebuilding the image; versions are recorded in every result.
- **Prompt injection through code:** the `Q` items carry far more attacker text than any M5 item (12 000 characters). Structural controls (no tools, no actions, verifier, text-only rendering) bound the effect; integrity attacks (a planted "this function is benign") are detected, not prevented.
- **capa / Ghidra disagreement:** function boundaries and ELF bases differ between vivisect and Ghidra; file-VA containment (RT8) handles most cases; misses are shown as "capability not located in a function".
- **Supply chain:** Ghidra zip and radare2 deb verified by pinned SHA-256, the JDK by image digest; a pinned version ages, and updating is a deliberate rebuild with the spike's checks re-run.
- **Licenses:** redistributing the image (not planned) carries GPL (Ghidra native helpers, JDK) and LGPL (radare2) source obligations; running it for the user's own use carries none (not legal advice). Phase 11 records the notices.
