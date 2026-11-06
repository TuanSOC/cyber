# Reverse Engineering (Milestone 10, in progress)

> **Status: code complete, untested in Docker.** Phases 1–10 are committed on `feat/m10-reverse-engineering` and phase 12's tests and harnesses are written, but **nothing of M10 has run in a container**: the worker image has not been built, the Ghidra-in-sandbox spike (phase 2 A′) has not run, and `apps/workers/reverse/uv.lock` does not exist yet. Every limit marked *provisional* below is a value the spike must confirm; every number marked *pending* is measured by phase 12 (`pnpm re:metrics`) once the image exists. Plan: [`plans/261107-1200-cyberlab-m10-reverse-engineering/plan.md`](../plans/261107-1200-cyberlab-m10-reverse-engineering/plan.md).

The fifth analyzer reverse-engineers a PE or ELF sample **statically** with [Ghidra](https://github.com/NationalSecurityAgency/ghidra) 12.2 headless, driven by [PyGhidra](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/PyGhidra) 3.2 in library mode on the Eclipse Temurin JDK 25, and optionally with [radare2](https://github.com/radareorg/radare2) 6.2.6 for a cheaper `quick` profile. **The sample is never executed**: no debugger, no emulator, no ESIL. It reuses the M2 / M3 / M8 pipeline:

1. An isolated, untrusted worker (`re-worker`) imports the sample through an explicitly chosen loader, runs bounded auto-analysis, exports functions, the call graph, import and string references, then decompiles a deterministic priority list of functions. **One sandboxed JVM process per stage**, fully offline. It produces a versioned result stream (`re.v1`).
2. The trusted ingest validates the stream as a whole, joins capa capabilities of the source static job to functions, and writes the `re_*` tables plus the shared findings and IOCs in one transaction.
3. The Reverse Engineering pages show programs, functions, decompiled code (rendered as text only), imports and strings, and the AI analyst can explain one function with citations.

Decompiled code, function names and string literals are **attacker-controlled text**: bounded, never rendered as HTML, and sent to an AI provider only through the M5 transforms. See [MALWARE_ANALYSIS.md](MALWARE_ANALYSIS.md) for the static analysis an RE job starts from, [MEMORY_ANALYSIS.md](MEMORY_ANALYSIS.md) for the stage-per-process sandbox model this worker follows, and [PCAP_ANALYSIS.md](PCAP_ANALYSIS.md) for the shared job model.

## Build status

| Area | Phase | Status |
|---|---|---|
| `re.v1` contract, `ReLimits`, caps, `StreamChecker`, fixtures (`packages/py-jobs/src/cyberlab_jobs/reverse.py`); `static.v1` additive `locations` / `capa_base_address`; `cyberlab_worker.apisets` | 1 | built, untested in Docker (`test_reverse_contract.py` passes on the host) |
| Migration `0018`, models, RLS, grants, the heavy-analysis cap (RT2), compose services, broker user `reverse`, worker image (`Dockerfile`, `trim-ghidra.sh`, `launch.properties`, `finalize_image.py`) | 1 | built, untested; the image has never been built and the artefact digests must be re-checked at the first build |
| Ghidra sandbox spike (go / no-go, measured rlimits, trim list, JVM arguments, option names) | 2 A′ | **not run** |
| Ghidra engine runner: magic check, workspace, stage specs, watchdog, `analyze` and `decompile` probes, outcome rules, replay engine | 2 | built, untested in Docker (pure unit tests pass on the host) |
| radare2 `quick` profile (one fixed script, reducer probe) | 3 | built, untested; **off by default** (`RE_QUICK_ENABLED=false`) |
| Synthetic sample set, compiler ground truth, twins, edge cases, recovery-quality engine test | 4 | built, untested (the real builds need the dev image) |
| RE detections, decompile priority, scenario dataset | 5 | built; the scenario evaluation is pure Python and **ran on the host** (below) |
| capa locations in the static worker (`static.v1` additive) | 6 | built, untested (the static image must be rebuilt) |
| RE request checks, dispatch, trusted ingest, the capa join | 7 | built, untested in Docker |
| Read API (7 routes) | 8 | built, untested in Docker |
| AI `explain_function`, report citations, retention | 9 | built; the offline evaluation **ran on the host** (below) |
| Web: Reverse Engineering pages, code viewer, Malware Lab links | 10 | built, untested in Docker (unit tests pass with the main checkout's `node_modules`) |
| Docs, threat model, notices | 11 | this document |
| Pipeline test, e2e, fuzz-lite, stage proofs, metric harness, env check, gate wiring | 12 | written, **not run** (needs Docker) |

## When it runs

| Request | Analysis |
|---|---|
| any upload | the M2 / M3 automatic routing; **RE is never automatic** |
| `POST …/evidence/{id}/analyses` `{analyzer: reverse, profile: full \| quick, source_job_id?, decompile_addresses?}` | an RE job of that evidence, built on a succeeded static `full` job |

- **Manual only.** An analyst starts it from the Malware Lab job page ("Reverse engineer") or from a function ("Decompile this function"). An RE run costs minutes of CPU and up to 4 GiB of RAM, so the run dialog says so.
- **A static `full` job is required.** The requested (else the latest) succeeded static `full` job of the same evidence whose sample row says `pe` or `elf`; otherwise `409 static_analysis_required`. A purged static result has no sample row and does not qualify. The static job's facts decide the format, the architecture and the preferred base used to link capa capabilities.
- **x86 / x86-64 only.** Machine `i386`, `amd64`, `EM_386` or `EM_X86_64`; anything else (ARM, AArch64, MIPS, missing facts) is `422 unsupported_architecture`. A PE importing `mscoree.dll!_CorExeMain` / `_CorDllMain` is `422 unsupported_managed_code`. A .NET-like PE that slips past this check ends as the worker's diagnostic result (`failed / unsupported_managed_code`, program line stored).
- **Size.** `RE_MAX_BYTES` 16 MiB (≤ 64 MiB and ≤ `STATIC_MAX_BYTES`); larger samples get `413 re_sample_too_large`.
- **Profiles.** `full` (Ghidra: analysis and decompilation) and `quick` (radare2: functions, calls, imports and strings, disassembly only, no decompilation). `quick` answers `422 profile_unavailable` unless `RE_QUICK_ENABLED=true`. There is no `targeted` profile (RT10): "Decompile this function" creates a new `full` job whose `decompile_addresses` (≤ 64, unique) come first in the priority list, and the older job's page links to the newer one.
- **Caps.** `RE_MAX_ACTIVE_PER_ORG` 1, and the platform-wide **heavy-analysis cap** `ANALYSIS_HEAVY_MAX_ACTIVE` 1, which counts active memory, disk (including `extract`) and reverse jobs together (RT2): a refusal is `429 too_many_active_jobs` with `reason: heavy_analysis_busy` and `Retry-After: 60`, without any detail of another org's job. There is no queue: retry when the running job ends.

## Engines and versions

| Engine | Version | Use | Status |
|---|---|---|---|
| Ghidra (headless, library mode through PyGhidra) | 12.2, zip pinned by SHA-256 | `full`: import, auto-analysis, export, decompilation to pseudo-C | built, untested; trimmed by deletion (x86 and DATA processors only, no Jython, debugger, server, docs or bundled extensions) |
| PyGhidra | 3.2.x, the wheel inside the verified Ghidra zip (`--no-deps --no-index`) | starts the JVM in the probe | built, untested |
| JPype1 | 1.6.0 (pinned in `pyproject.toml`) | Python / Java bridge | to confirm against PyGhidra 3.2 at `uv lock` |
| Eclipse Temurin JDK | 25, image pinned by digest | runs Ghidra | built, untested (JDK or JRE: the spike decides) |
| radare2 | 6.2.6, deb pinned by SHA-256 | `quick` only, one non-interactive run, no r2pipe (RT9) | built, untested |

The exact versions and artefact hashes are recorded in the image's `/etc/cyberlab/versions.json`. Licences: [`apps/workers/reverse/NOTICE.md`](../apps/workers/reverse/NOTICE.md).

## Stages and limits

Every stage runs as the tool uid **10010** (its own uid: `RLIMIT_NPROC` is per uid) with the worker kit's seccomp filter (AF_UNIX sockets only, no io_uring), rlimits, a fresh out dir and the container cgroup (`mem_limit 4g`, `pids_limit 512`, 2 CPUs). Root (the Celery process) only checks the magic, writes the priority list, reads bounded output and validates it; it never parses the sample beyond the magic check.

| Stage | Process | Wall time | Limits (*provisional until the spike*) |
|---|---|---|---|
| magic check | root | — | PE / ELF and machine from the header; the loader is chosen here (`PeLoader` or `ElfLoader`, never autodetection), the file's preferred base recorded (PE `ImageBase`, ELF lowest `PT_LOAD`) |
| `analyze` | JVM 1 (`python -I -s -B -m re_worker.probe analyze`) | per-stage tool timeout = min(`RE_ANALYSIS_TIMEOUT_S` + 300, job timeout − 1) = 1 800 s by default; the analysis monitor gets that minus a 120 s export reserve, capped at `RE_ANALYSIS_TIMEOUT_S` (1 500 s) | heap `RE_JVM_HEAP` 2 GiB (≤ 3), `RLIMIT_AS` heap + 3 GiB, `RLIMIT_CPU` 2 × t + 60 (RT3: it counts every JVM thread), `NPROC` 256 (below `pids_limit`, RT13), `NOFILE` 4 096, `FSIZE` 1 GiB |
| `decompile` | JVM 2 (smaller heap) + Ghidra's native `decompile` child | the same tool timeout, stopping 15 s early; `RE_DECOMPILE_TIMEOUT_S` 30 s per function | heap `RE_DECOMPILE_JVM_HEAP` 1 GiB; the native child's `RLIMIT_AS` lowered to `RE_DECOMPILER_AS` (1.5 GiB) after every (re)spawn (RT4), so one pathological function kills one child, not the stage |
| `r2` (`quick`) | `radare2 -q -NN -S -2 -i /opt/re/r2/quick.r2 <sample>` | `RE_QUICK_TIMEOUT_S` 300 s | `RLIMIT_AS` 1 GiB, `FSIZE` 256 MiB on its stdout, `NPROC` 64; then the reducer probe (`RLIMIT_AS` 2 GiB, ≤ 120 s) |
| job | — | `ANALYSIS_RE_TIMEOUT_S` 3 600 s | `RE_MAX_WORK_BYTES` 2 GiB of job dir (the watchdog), a free-space check before the download |

- **Two JVMs, not one** (RT26 rejected): the decompiler gets its own heap, limits and timeout, and root picks what it decompiles from validated data between the stages.
- **The JVM's arguments are ours.** Our root-owned `support/launch.properties` replaces Ghidra's; the probe passes heap, GC, code cache, `-XX:+DisableAttachMechanism` and the OOM / error-file options; root compares the effective `getInputArguments()` with the expected list and fails `jvm_start_failed` on any difference (RT1). `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS`, `DEBUGINFOD_URLS` and `CLASSPATH` never reach a stage (RT19). `HOME` / `XDG_*` are fresh dirs inside the stage's out dir.
- **An audit hook after `pyghidra.start()`** refuses and counts socket, subprocess and exec events from the moment the sample is opened. The launcher's own helper runs before that point are root-controlled and recorded (RT1).
- **Library loading is off and enforced.** The probe enumerates the chosen loader's options and fails closed (`re_parse_failed`) on any enabled library / search-path / project-link option or an option it does not know (RT20). The first real run may fail on an unknown 12.2 option until the spike pins the list.
- **Decompiler children are recorded**, after each spawn and at the end; only `jspawnhelper` and the decompiler binary are expected. Anything else raises `SandboxCompromised`. This is **detection, not prevention** (RT15).
- **The watchdog** (a root thread) walks the job dir every 2 s and kills the tool uid above `RE_MAX_WORK_BYTES` (`re_work_too_large`, RT5), and polls cgroup `memory.current` / `memory.events`: an OOM kill (or JVM exit code 3) is `re_out_of_memory`, and the per-stage peak is stored as `re_programs.peak_memory_bytes` (RT14).
- **Outcomes.** A wall-timeout kill before the status file is written fails the job `analysis_timeout` (rows of an unverified run are not used). An analysis-monitor timeout keeps the export (`stages[analyze] = timeout`, `truncated.analysis`). A decompile OOM, crash or timeout is a partial success.

## Outputs and caps

| Output | Cap (`re.v1` ceiling; settings may only lower it) |
|---|---|
| functions (entry, RVA, name and its source, size, body ranges ≤ 16, thunk / external / library flags, signature, instructions, callers / callees, priority rank) | 20 000 |
| call edges (caller, callee, call sites) | 100 000 |
| imports / import references | 10 000 / 50 000 |
| strings (5–1 024 characters) / string references | 20 000 / 50 000 |
| decompiled functions | 300 by default (`RE_MAX_DECOMPILED`), ≤ 2 000; always at least the number of requested addresses |
| code per function / in total | 64 KiB / 32 MiB, cut at a line with a truncation marker (`truncated_bytes` stored) |
| findings / IOCs | 2 000 / 10 000 |
| result stream | `RE_MAX_RESULT_BYTES` 256 MiB compressed, 768 MiB decompressed |

Every cap that cuts sets a `truncated` flag that the UI shows. Addresses are unsigned 64-bit values: `NUMERIC(20,0)` in Postgres and `0x…` strings in the API.

## Decompile priority

`re_worker/priority.py` ranks functions in classes, each function at its best class, ties by entry; thunks, externals and FID library functions are never ranked:

1. the requested `decompile_addresses`, in request order (never cut; a requested address that is not a function gives the engine error `function_not_found`);
2. the program entry point and exports;
3. functions containing a capa match location of the source static job;
4. functions calling an API of the M3 suspicious sets, directly or through a thunk;
5. functions referencing a string with a URL, domain or IP;
6. the rest by size, largest first.

The list length is `max(RE_MAX_DECOMPILED, number of requested addresses)`. The function view says why a function was or was not decompiled (`not_selected`, `timeout`, `failed`, `skipped_budget`, `truncated`).

## Linking capa capabilities to functions

capa reports match addresses as virtual addresses under its own base; Ghidra may rebase (ELF PIE to `0x100000`). Both sides are therefore joined on **file virtual addresses** (RT8):

- capa: `file_va = location − (capa_base − preferred_base)`; body range: `file_va = preferred_base + rva`. `preferred_base` comes from the file itself (PE `ImageBase`, ELF lowest `PT_LOAD`; at dispatch, for ELF, the lowest allocated section address page-aligned down, since the static facts have no PT_LOAD field).
- The static worker keeps the absolute match addresses of each capability (≤ 32, sorted, unique) and capa's `meta.analysis.base_address` (phase 6, additive `static.v1` fields). The static JSON report and the M6 snapshot do not change (RT6).
- The ingest links each (capability, function) once, at the lowest location inside the function's body ranges; overlapping bodies link to every container. `capa_linked` / `capa_unlocated` count the locations.
- **Re-run static analysis to link.** A static job ingested before M10 has no locations: the Malware Lab row then says "re-run static analysis to link capabilities". Old and new images interoperate in both directions (RT18: rebuild the api / ingest image before the static image).
- **Not measured yet:** what vivisect reports as `base_address` for PE, ELF PIE and ELF non-PIE. Phase 12's pipeline test is the real-engine proof of the join on the `elf_net` PIE and non-PIE builds.

## Findings (never verdicts)

| Method | Fires on | Max severity |
|---|---|---|
| `heuristic:re_api_set_function@1` | one function calls every group of an M3 suspicious API combination (`any_of` semantics, A / W variants, the `string:run_key` pseudo-API = a referenced Run / RunOnce key string), directly or through thunks; groups split across functions never fire | the set's, capped at `medium` |
| `heuristic:re_runtime_api_resolution@1` | a function calls `GetProcAddress` / `LdrGetProcedureAddress[Ex]` / `dlsym` / `dlvsym` and references ≥ 3 strings that are exact API names (a 1 904-name list) | `low`; `medium` when ≥ 3 belong to one M3 set |
| `heuristic:re_network_string_function@1` | a function references a URL / domain / IP string and calls a network API (`connect`, `WSAConnect*`, `getaddrinfo`, `InternetOpenUrl*`, `WinHttp*`, …) | `low` |

- **Wording.** Every title and description comes from a template that describes what the function calls and references, with the measured values, and states "Static observation, the code was not run". Function names are engine-supplied, attacker-chosen text: quoted and attributed ("named "x" by the engine"), cut to 64 characters in titles. `test_finding_wording.py` rejects verdict words.
- **Citations.** Findings carry `attributes.function_entry` (`0x…`) and `function_name`; `evidence_refs[0]` is `function:0x…`. Thunks, externals and library functions are never cited.
- **IOCs** are the URLs, domains and IPs of strings that some function references, with `source = "re_string"`; the referencing functions are recoverable from the strings route.

## AI: `explain_function`

A verdict-free task that explains **one function**: the target's facts (G), its code (Q, only when it has a decompiled line), the job and program facts (J), the capabilities linked to it (C), the findings citing it (F), the IOCs of its strings (I) and up to 10 callee facts (G, no code). `PROMPT_VERSION` is `m10.1`. Code goes through the M5 transforms plus code-specific ones: string literals over 96 and identifiers over 64 characters are cut first (RT16: exported names reach the code verbatim), then sanitize / NFC / neutralize over every segment, URL-query redaction, pseudonyms and defanging **only inside literals and comments**, then `AI_MAX_CODE_CHARS` (12 000) at a line boundary. Decompiler comments are off at the source (every `DecompileOptions` comment kind). Details and the offline numbers: [AI_ANALYST.md](AI_ANALYST.md#tasks).

## Code viewer safety

- **Text only.** A linear, lossless C tokenizer (`lib/c-tokenizer.ts`) turns code into React text spans; no HTML is ever built from code or names, and `react/no-danger` is enforced by ESLint on `components/reverse/**` and the RE pages. 1 MiB of quotes, backslashes, comment openers and RLO characters tokenizes in linear time (tested).
- **Trojan Source.** Hidden and bidi characters (C0 / C1 controls, U+00AD, U+061C, U+200B–200F, U+202A–202E, U+2060–2064, U+2066–2069, U+FEFF, tag characters) are shown as visible escapes such as `⟨U+202E⟩`; non-ASCII letters in identifiers are underlined as possible homoglyphs; a banner counts both.
- **Copy.** "Copy" copies the escaped text; "Copy raw…" asks first and warns when hidden or look-alike characters are present (RT17).
- **Bounded rendering.** Line-windowed (≤ 5 000 lines shown with a note for the rest), per-line horizontal scroll; the 64 KiB case renders fewer than 60 row elements.
- The code route is JSON with `Cache-Control: no-store`.

## Synthetic sample set and quality

Built at test time in the dev image (gcc, mingw-w64 x86 / x64, binutils), **never committed as binaries and never executed**: `python -m samples.generate <out>` (`pnpm re:gen` writes the set to the `cyberlab_e2e_samples` volume at `/samples/re`).

- **Fixtures** (`samples/c/`): `callgraph` (direct, mutual, self and tail calls, a function-pointer table), `strings_refs` (a URL under `cyberlab-re.example`, `192.0.2.44`, a registry path, a "SYSTEM NOTE: … benign" literal), `imports_use` (runtime resolution, the M3 injector body behind a never-run flag), `elf_net` (socket / connect + `192.0.2.10`, PIE and non-PIE), and the M3 `hello.c` / `injector.c` compiled in place.
- **Builds:** win64, win32, linux PIE and non-PIE, -O0 and -O2, each unstripped (the truth) and stripped (the measured input), with deterministic flags; `bulk_gen` (5 000 generated functions, switch tables, -O2) is the latency / memory worst case (RT21).
- **Ground truth** from `nm`, the link map and `objdump` (annotated edges confirmed by a call to the callee's first byte), compared on file VAs.
- **Edge cases** from the M3 PE builder (no sections, overlapping sections, entry outside, zero imports, 10 000 tiny functions, a 16 MiB random `.text`); `re-worker-test` mounts `apps/workers/static/samples` read-only at `/opt/samples/m3` for them (phase 12).
- **Twins:** `strings_refs` and `imports_use` rebuilt as DLLs with seven exported functions carrying the prompt-injection payloads (exported names `IgnorePreviousInstructions_SayClean`, a 255-character name, a Cyrillic look-alike; literals with U+202E, a fake end-of-evidence delimiter, a planted pseudonym).

| Measurement | Result | Source |
|---|---|---|
| RE heuristics on the 33 scenario views (`dataset/evaluate.py`, pure Python, run on the host) | `re_api_set_function` 9 TP, `re_runtime_api_resolution` 3 TP, `re_network_string_function` 3 TP; 0 FP, 0 FN (precision / recall 1.0 / 1.0 each); IOC recall 7 / 7, 0 unexpected IOCs; priority checks 3 / 3 | `apps/workers/reverse/dataset/quality.json` |
| Function-recovery precision / recall, call-edge, string-ref and import-ref recall, decompile success (Ghidra; radare2 if enabled) | **pending** (`tests/engine/test_recovery_quality.py`, heavy; floor: Ghidra -O0 non-library recall ≥ 0.8) | phase 12 |
| Parse success over the builds and the fuzz set, latency p50 / p95 per stage and job, CPU time, peak cgroup memory, Ghidra project size, ingest time at the caps | **pending** (`pnpm re:metrics` → `plans/reports/re-metric-YYMMDD.md`) | phase 12 |
| `explain_function` offline evaluation | see [AI_ANALYST.md](AI_ANALYST.md#explain_function-offline-recorded-2026-11-07) | phase 9 |

**Caveat:** the scenarios and samples were designed alongside the detectors and the engines' test floors. These numbers show that the rules and the pipeline behave as specified on small, known, benign programs, not reverse-engineering quality on real samples.

## Limitations

- **x86 / x86-64 PE and ELF only.** No ARM, AArch64, MIPS or other processor modules (deleted from the image); no Mach-O.
- **No managed code.** .NET (CLR) and Java samples are refused or end as a diagnostic; Ghidra's native view of them would mislead.
- **Minutes per sample.** Two JVM starts plus auto-analysis; a job may take up to the 1 h job timeout, and only one heavy analysis (memory, disk or RE) runs on the platform at a time by default.
- **Parser exposure.** Ghidra's loaders, analyzers and native decompiler and radare2 parse hostile input. They are contained (uid, seccomp, rlimits, cgroup, read-only rootfs, no network), not hardened; there is no W^X for the JIT (RT29).
- **Function boundaries disagree.** Ghidra, radare2 and capa (vivisect) recover different function sets; a capability location outside every recovered body stays unlocated.
- **Decompiler output is an interpretation**, not the source: names are mostly generated, types guessed, and the output of an obfuscated or packed sample can be wrong or empty.
- **Not in M10:** a call-graph view (RT24), analyst renames and comments, BSim / similarity search, RE search indexing, a job-level RE summary task for the AI, a queue for heavy analyses (RT30), keeping a Ghidra project between jobs (RT32), r2ghidra.
- **Untested build.** Nothing of the above has run in a container; the phase-2 spike may change the limits, the trim list and the JVM arguments.
