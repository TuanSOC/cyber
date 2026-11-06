# Research: Ghidra headless and radare2 for an offline reverse-engineering worker (M10)

Date: 2026-11-07. Method: GitHub releases API, PyPI JSON API, the Ghidra 12.x docs (`ghidradocs.com`, the 12.2 `GettingStarted`), the Ghidra repository tree at `Ghidra_12.2_build`, the capa source (`capa/render/result_document.py`), radare2 / rizin release notes, and the CyberLab code (M3 static worker, worker kit, AI analyst). **[V]** = verified at the cited source on this date. **[I]** = inferred, remembered or unverified: the phase-2 spike must confirm it. No binary was downloaded, no container was run. This is not legal advice.

## 1. Versions and packaging

| Item | Value | Status |
|---|---|---|
| Ghidra latest | **12.2** (tag `Ghidra_12.2_build`, 2026-10-22); zip `ghidra_12.2_PUBLIC_20261016.zip`, 569.7 MB; the release body lists its SHA-256 | [V] GitHub releases API |
| Ghidra line | 12.0.x (2026-01..03, zip ~510 MB), 12.1.x (2026-05..09, ~570 MB), 12.2 | [V] |
| JDK for 12.2 | "Java 25 64-bit Runtime and Development Kit (JDK)" (12.0 needed JDK 21) | [V] 12.2 GettingStarted; [V] search summary for 12.0 |
| Python for PyGhidra | 3.9 – 3.15 | [V] 12.2 GettingStarted |
| Minimum host | 4 GB RAM, 1 GB disk for the binaries | [V] 12.2 GettingStarted |
| PyGhidra | **3.2.0** (2026-10-22), Apache-2.0, `requires-python >= 3.9`, depends on `JPype1 >=1.5.2, !=1.6.0, !=1.7.0`, `typing_extensions`, `packaging`; 3.x requires Ghidra 12.0+ | [V] PyPI JSON |
| PyGhidra offline install | wheel bundled in `<install>/Ghidra/Features/PyGhidra/pypkg/dist` (`pip install --no-index -f …`) | [V] GettingStarted; whether JPype's wheel is bundled too is [I] (take it from PyPI, hash-pinned in `uv.lock`) |
| Script engines | since 12.0 the default Python engine is PyGhidra (CPython 3 via JPype); Jython (Python 2.7) scripts need a `# @runtime Jython` header | [V] 12.0 release-notes summary |
| radare2 latest | **6.2.6** (2026-11-05), `radare2_6.2.6_amd64.deb` 8.9 MB (+ `-dev` 262 KB) | [V] GitHub releases API |
| rizin latest | 0.9.1 (2026-06-29), static x86_64 tarball 137.6 MB | [V] GitHub releases API |
| r2pipe (Python) | 2.1.0 (2026-10-19), MIT, no dependencies; transports: pipe, TCP, HTTP | [V] PyPI JSON |

**Image size estimate** (to be measured by the spike):
- Ghidra unpacked ≈ 1.0–1.3 GB [I] (the zip is 570 MB compressed); a JDK 25 ≈ 300–350 MB [I]; python:3.12-slim + venv ≈ 250 MB [I]. Untrimmed **≈ 1.6–1.9 GB**, in line with the brief's 1.5–2 GB.
- Trimming candidates (deletions only, which Apache-2.0 allows; keep every `LICENSE` / `licenses/` file) [I]: `docs/`, `Extensions/` (optional extension zips), `server/` (Ghidra Server), `Ghidra/Debug/` (the debugger: traces, Python agents), `Ghidra/Features/Jython` (Python 2), processor modules other than `x86` and `DATA`. Target **≤ 1.2 GB** [I]. The spike verifies that headless import + analysis + decompile still work after each deletion (module dependencies are declared in `Module.manifest`; a missing dependency fails at startup, which the spike would see).
- radare2 adds ≈ 30 MB installed [I] (the deb is 8.9 MB).

## 2. Licenses

| Component | License | Obligation for CyberLab | Status |
|---|---|---|---|
| Ghidra | Apache-2.0 | keep `LICENSE` and NOTICE files; modifications allowed (trimming is a modification: state it in our NOTICE) | [V] (well known; repo `LICENSE`) |
| Ghidra `GPL/` components | GPL (the repo's `GPL/` tree holds `DemanglerGnu`, `GnuDisassembler`, `DMG`, own `licenses/`) | shipped as separate native executables, never linked by us; unmodified; keep their license files. Distributing the image to third parties then carries the GPL source obligation for those binaries (the Ghidra source tag is public) | [V] tree listing; which binaries ship in the release zip is [I] |
| PyGhidra, JPype1 | Apache-2.0 | notices | [V] PyGhidra; JPype1 Apache-2.0 [I] |
| JDK (Temurin 25) | GPLv2 + Classpath Exception | none for running; on image redistribution, the upstream source offer applies | [I] |
| radare2 | LGPL-3.0 | unmodified distro build, used as a separate process: no obligation on our adapter; on image redistribution, provide the corresponding source (pin the source tarball in `versions.json`) | [I] (well known) |
| r2pipe | MIT | notice | [V] |

**Contrast with M8 (VSL):** none of these licenses reaches the adapter code. Apache-2.0 and LGPL-3.0 (used as a separate process) do not require publishing the RE worker. This removes the M8 "user legal decision" class of risk for M10.

## 3. Headless analysis: two ways to drive Ghidra

1. **`analyzeHeadless`** (`support/analyzeHeadless`): `analyzeHeadless <project_location> <project_name> -import <file> [-postScript X.py args] [-noanalysis] [-readOnly] [-deleteProject] [-analysisTimeoutPerFile s] [-max-cpu n] [-loader L] [-processor id] [-scriptPath …] [-log p] [-scriptlog p] [-mirror]` [V 12.1 analyzeHeadlessREADME]. The script sets `MAXMEM=2G` by default, overridable by `GHIDRA_HEADLESS_MAXMEM` [V search summary of the script]. Scripts are files on a script path; Java scripts are compiled at run time through OSGi bundles [I].
2. **PyGhidra library mode** (recommended): CPython imports `pyghidra`, starts the JVM in-process through JPype and calls the Ghidra API directly [V README 12.2]:
   - `pyghidra.start(verbose=False, *, install_dir: Path = None) -> PyGhidraLauncher` (else `GHIDRA_INSTALL_DIR`);
   - `launcher.add_vmargs("-Xmx…")` to set JVM options (use a `HeadlessPyGhidraLauncher` built explicitly so the vmargs are added before the start) [V for `add_vmargs`; the exact launcher class name is I];
   - `open_project(path, name, create=False) -> Project`;
   - `program_loader() -> ProgramLoader.Builder` (load a file with an explicit loader);
   - `@contextmanager program_context(project, path) -> Program`;
   - `analyze(program, monitor=None) -> str` (auto-analysis; the monitor gives cancellation / timeouts);
   - `ghidra_script(path, project, program=None, …)` (not needed);
   - the older `open_program()` / `run_script()` are deprecated in 3.x.

   Why library mode: no script path, no run-time script compilation, no `analyzeHeadless` argument parsing; the same "drive the library from our own probe" pattern as M8's Volatility probe; exports are written directly as bounded JSONL by our Python code.

**Export API** (Ghidra Java API, called from Python) [I: names from the long-stable Ghidra API, verified by the spike]:
- functions: `program.getFunctionManager().getFunctions(True)`; `f.getEntryPoint()`, `f.getName()`, `f.getSymbol().getSource()` (USER_DEFINED / IMPORTED / ANALYSIS / DEFAULT), `f.getBody()` (an `AddressSetView`: ranges), `f.isThunk()`, `f.isExternal()`, `f.getSignature()`, `f.getCallingConventionName()`, `f.getCalledFunctions(monitor)` / `f.getCallingFunctions(monitor)`;
- call sites: `ReferenceManager.getReferencesFrom/To` with `RefType.isCall()`;
- imports: `SymbolTable.getExternalSymbols()`, `ExternalManager.getExternalLibraryNames()`; usage = call references to the thunk / IAT pointer of each external;
- strings: `DefinedDataIterator.definedStrings(program)` (or the listing's defined data with a string data type), then `getReferencesTo(address)` → `getFunctionContaining(fromAddress)`;
- decompiler: `DecompInterface()`, `openProgram(program)`, `setSimplificationStyle("decompile")`, `decompileFunction(f, timeout_s, monitor)` → `DecompileResults.decompileCompleted()`, `getDecompiledFunction().getC()`, `getErrorMessage()`; `dispose()`.
- Function ID (FID): Ghidra ships FID databases for common Visual Studio runtimes and tags matched library functions [I]; mingw / glibc CRT functions are mostly not covered [I].

**The decompiler is a native C++ child process** (`Ghidra/Features/Decompiler/os/linux_x86_64/decompile`) that the JVM spawns per `DecompInterface` and feeds over pipes [I, long-standing design]. Consequences: the sandbox must allow `execve` of that one binary and `RLIMIT_NPROC` must count it; its memory is outside the JVM heap; a crash or hang ends that decompile (the Java side reports an error / timeout) [I].

## 4. Resource needs (the host has 8–12 GB RAM)

All numbers [I]: practitioner experience and Ghidra defaults, to be measured by the spike on our samples.
- **JVM:** headless default heap 2 GiB (`MAXMEM=2G`). Small binaries (≤ 1 MiB) analyse within 1–2 GiB heap; 10–20 MiB binaries may need 3–4 GiB. Plus metaspace / code cache / threads ≈ 300–600 MiB, plus the decompiler process 100–500 MiB.
- **Proposed container:** `mem_limit: 4g`; JVM `-Xmx2g` (setting, ≤ 3g), `-XX:+UseSerialGC`, `-XX:ActiveProcessorCount=2`, `-XX:ReservedCodeCacheSize=128m`, `-XX:MaxMetaspaceSize=512m`, `-XX:CompressedClassSpaceSize=256m`, `-XX:MaxDirectMemorySize=256m`, `-Xss1m`, `-XX:-UsePerfData` (no `/tmp/hsperfdata`), `-XX:+ExitOnOutOfMemoryError`, `-XX:ErrorFile=<out>/hs_err.log`, `-Djava.awt.headless=true`, `-Duser.home=<out>/home`, `-Djava.io.tmpdir=<out>/tmp`, `MALLOC_ARENA_MAX=2`.
- **RLIMIT_AS and the JVM:** the JVM reserves far more virtual memory than it commits (heap reserve, class space, code cache, thread stacks). An `RLIMIT_AS` of heap + 3 GiB is a reasonable starting point [I]; the cgroup `mem_limit` is the real bound. The spike must find the smallest `RLIMIT_AS` that starts the JVM reliably.
- **RLIMIT_NPROC** counts threads per uid: a JVM with 2 active CPUs and SerialGC runs ≈ 20–40 threads, Ghidra adds worker pools [I]. Start at 512; `nofile` 4096 (Ghidra opens hundreds of jars) [I].
- **Time:** JVM + Ghidra start 5–15 s; auto-analysis of a 100 KiB mingw program 10–30 s; 1–5 MiB binaries 1–10 min; 16 MiB can exceed 30 min [I]. Decompile: tens of ms to seconds per function, with pathological functions hitting the per-function timeout (the GUI default is 30 s [I]).
- **Disk:** the Ghidra project of a 16 MiB binary can reach several hundred MiB [I]; `/work` must not be a memory-backed tmpfs in prod (tmpfs pages count against the container's memory cgroup).
- **Analyzers worth turning off** for cost or exposure [I: names checked by the spike against `program.getOptions("Analyzers")`]: "Decompiler Parameter ID" (very slow), "Aggressive Instruction Finder" (off by default), "PDB Universal" / "PDB MSDIA" (symbol-server lookups; PDBs are never present), "DWARF" external debug-file search / debuginfod (keep DWARF on the binary's own sections), "Embedded Media". Keep "Function ID", "Non-Returning Functions", "Reference", "Stack", "ASCII Strings", "Apply Data Archives", "Windows x86 PE RTTI", "Decompiler Switch Analysis".
- **radare2:** a 100 KiB binary with `aaa` analyses in < 5 s within ~100–300 MiB RSS; big binaries can blow up time with `aaa` / `aaaa` (ESIL emulation) — bound with `e anal.timeout` and our timeout [I].

## 5. radare2 / rizin as the lighter alternative

- **JSON commands** (r2pipe `cmdj`) [I: verified against 6.2.6 by the phase]: `ij` (info), `iij` (imports), `iEj` (exports), `izj` (strings in data sections), `aflj` (functions: offset, name, size, nbbs, callrefs / codexrefs), `agCj` (global call graph), `axtj @ <addr>` (xrefs to), `pdfj @ <addr>` (disassembly of a function), `aa` / `aac` / `aaa` (analysis levels).
- **Decompilation:** r2's `pdc` is a pseudo-C rendering of disassembly, not a decompiler; real decompilation needs the **r2ghidra** plugin (Ghidra's C++ decompiler embedded, built from source with `r2pm`, C++ toolchain at build time) [I]. Rizin has rz-ghidra the same way.
- **Memory safety:** radare2 is C. The 6.2.6 notes alone list "heap overflow and out-of-bounds read/write prevention across multiple parsers", stack exhaustion on cyclic types, integer overflows, use-after-free, and fuzzing fixes for ELF, PE, DEX and DWARF parsers [V release notes]. Ghidra's loaders and analysis are Java (memory-safe; DoS still possible), its decompiler and demangler are native.
- **Command-language injection:** r2 is driven by a command language (`;` chaining, `!` shell escape, `` ` `` substitution, `@` temporary seek). The 6.2.6 notes add "Reject unsafe r2 command substitutions" and "Command injection prevention in symbol names and version strings" [V], i.e. this class has had real bugs. **Rule:** never build an r2 command from a string that came from the binary; only fixed commands plus integers we format (`pdfj @ 0x%x`).
- **r2 sandbox:** `-S` is `-e cfg.sandbox=true` (wraps file, network and exec access; no shell escapes); kernel-level sandboxing only on macOS / OpenBSD [V Debian `doc/sandbox/README.md`]. CVE-2026-112077 (6.2.0 / 6.2.2) was a sandbox bypass through an over-permissive HTTP sandbox policy, and `cfg.sandbox.grain` controls which capabilities are restricted [V CVE pages; the exact default semantics of `grain` are I]. The r2 sandbox is a second layer only; our OS sandbox (uid, seccomp, rlimits) is the boundary. Also start r2 with `-N` (no rc files, no user plugins) and HOME empty.
- **rizin** has the same profile (C, command language, rz-pipe, rz-ghidra) with a 137 MB static tarball; the requirement names radare2, so rizin adds nothing for us.

## 6. Engine choice

| Criterion | Ghidra 12.2 headless (PyGhidra) | radare2 6.2.6 (r2pipe) |
|---|---|---|
| Decompiled pseudo-C | yes, best-in-class open source | no (pdc pseudo); r2ghidra needs a C++ build |
| Function recovery, types, FID, RTTI | strong | adequate, weaker on stripped binaries [I] |
| Parser memory safety | Java loaders; native decompiler / demangler | C parsers with a steady stream of memory-safety fixes |
| Injection class | none in the API path (no command language) | command language; never interpolate binary strings |
| Image | ≈ 1.6–1.9 GB (trim to ≤ 1.2 GB) | ≈ 30 MB on top |
| RAM / time | 2–4 GiB, minutes | 0.1–0.5 GiB, seconds |
| License | Apache-2.0 (+ GPL native helpers) | LGPL-3.0 (separate process) |
| Named in `requirement.txt` §3 | "Ghidra", "Ghidra headless analyzer" | "radare2" |

**Recommendation:** **Ghidra 12.2 via PyGhidra library mode as the primary engine** (`full` profile: analysis + prioritized decompilation; `targeted` profile: decompile chosen functions), because decompiled code is the core value of RE for an analyst and for the AI "explain function" task, the loaders are memory-safe Java, and there is no command language to inject into. Its cost (image, 4 GiB container, minutes per sample) fits the host if the RE worker runs with concurrency 1, one active job globally, and heavy steps alone.

**radare2 as an optional second engine** for a `quick` profile (functions, imports and their callers, strings and their referencing functions, call graph, no decompilation) in the same image (+≈ 30 MB): seconds per sample, ~10× less RAM, and the requirement names it. It is explicitly cuttable (its own phase) without changing the contract: the profile stays in the enum and the API refuses it while `RE_QUICK_ENABLED=false`.

**Fallback if the spike fails** (Ghidra cannot run reliably inside the sandbox on this host): promote radare2 to the only engine (`quick` + bounded disassembly), defer decompilation to "Later", and record it. The contract already carries `engine`.

## 7. Security notes specific to decompilers

- **Parsing hostile binaries:** Ghidra past issues include XXE in project files (CVE-2019-16941 class) and path traversal in project archives (CVE-2019-17664 class) [I: the CVE ids are remembered, not re-checked]; we never import project archives or `.gzf` / `.xml` program files, only the single sample through an explicitly chosen loader (`PeLoader` / `ElfLoader`; never the container / filesystem loaders that open zip, 7z, ISO). Loader DoS (huge allocations, loops) is bounded by the timeout monitor, our timeout, the cgroup and `RLIMIT_AS`.
- **No library loading:** ELF / PE import options that search the filesystem for referenced libraries must be off ("Load External Libraries" / library search paths) [I option names], so a binary cannot make Ghidra read `/etc` or other files.
- **No network:** no Ghidra Server, no symbol server, no debuginfod; seccomp AF_UNIX-only plus the internal `analysis` network. The JVM has no SecurityManager any more (removed in JDK 24 [I]), so Java-side network denial rests on seccomp and the network. **Spike item:** confirm the JVM starts and runs with AF_INET / AF_INET6 sockets denied (the JDK may probe IPv6 support at network init; a denied `socket()` should be handled [I]).
- **Never execute samples:** neither engine runs native code. Ghidra's P-code emulator is not used; r2 never runs `ood` / `dc` (debugger) and ESIL emulation (`aaaa`, `aez*`) is not used.
- **Outputs are untrusted text:** function names (exports, symbols, debug info, RTTI), string literals, demangled names and the decompiled code itself carry attacker-chosen text (prompt injection, terminal escapes, bidi "Trojan Source" overrides, fake markup). Bound every field, strip NUL, keep the raw text only in DB rows rendered as text, and run the M5 transforms before any AI context.
- **UI:** render code as text nodes only (React escaping), with a linear-time tokenizer producing spans; show bidi / control characters visibly instead of applying them.

## 8. Linking to capa (M3)

- capa's result document stores, per rule, `matches: tuple[tuple[frz.Address, Match], ...]` with address types `absolute`, `relative`, `file`, `no_address` (+ dotnet / dynamic kinds) [V `result_document.py`]. Function-scope rules match at the function's address, basic-block rules at the block, instruction rules at the instruction [I].
- M3's `CapabilityRecord` keeps only `name`, `namespace`, `attack`, `mbc`, `matches` (a count) [V `cyberlab_jobs/static.py`]: **no addresses**. Linking needs an additive optional field (`locations`, absolute addresses, capped) in `static.v1` and a column in `malware_capabilities`, plus the base address capa used (`meta.analysis.base_address` [I]) so both sides join on RVAs (Ghidra may load ELF PIE at a different base than vivisect [I]).
- The join is containment: a capa location belongs to the Ghidra function whose body ranges contain its RVA (entry points may differ between vivisect and Ghidra).

## 9. Test data

- **No real malware** (`requirement.txt` §14). Reuse the M3 benign C sources (`apps/workers/static/samples/c/hello.c`, `injector.c`, cross-compiled with mingw-w64 at test time, never run) and add RE-specific benign C programs with a known call graph, known string references and known import usage, built with mingw (PE x86 / x64) and gcc (ELF x64), each in an unstripped and a stripped variant. Ground truth comes from the compiler's own symbol table / map file of the unstripped build (`nm`, `-Wl,-Map`).
- The M3 pure-Python PE / ELF builders give structurally valid files with random code bytes (robustness, fuzz seeds).
- Metrics this enables: function-recovery precision / recall on stripped builds, call-edge recall, string-xref recall, import-usage recall, decompile success rate, latency and peak RSS — all with the "synthetic, built alongside the tools" caveat.

## 10. Open questions for the spike (phase 2, time-boxed)

1. Does PyGhidra 3.2 + Ghidra 12.2 + JDK 25 start and analyse a mingw sample as uid 10010 under seccomp AF_UNIX-only + no io_uring, with `RLIMIT_AS` / `NPROC` / `NOFILE` set? Minimal working values?
2. JDK vs JRE: does PyGhidra's launcher accept a JRE (smaller), or does it insist on a JDK?
3. Which directories can be deleted from the install (size after trimming)?
4. Exact 12.2 analyzer option names; the library-loading and external-debug-file options.
5. Peak RSS and wall time per sample (hello, injector, the RE fixtures, a 4 MiB and a 16 MiB generated PE).
6. Does `program_loader()` let us force `PeLoader` / `ElfLoader` and refuse others?
7. Does the decompiler child process run under the inherited limits, and does a per-function timeout kill it cleanly?

## Sources
- Ghidra releases: https://api.github.com/repos/NationalSecurityAgency/ghidra/releases
- Ghidra 12.2 Getting Started: https://ghidradocs.com/12.2_PUBLIC/GettingStarted.html and https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/GhidraDocs/GettingStarted.md
- Headless analyzer README (12.1): https://ghidradocs.com/12.1_PUBLIC/support/analyzeHeadlessREADME.html
- PyGhidra README (12.2): https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/Ghidra_12.2_build/Ghidra/Features/PyGhidra/src/main/py/README.md
- Ghidra 12.0 changes (summary): https://www.mintlify.com/NationalSecurityAgency/ghidra/resources/changelog
- analyzeHeadless script / MAXMEM: https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/master/Ghidra/RuntimeScripts/support/analyzeHeadless
- Ghidra GPL tree: https://github.com/NationalSecurityAgency/ghidra/tree/Ghidra_12.2_build/GPL
- PyGhidra on PyPI: https://pypi.org/pypi/pyghidra/json
- radare2 releases: https://api.github.com/repos/radareorg/radare2/releases
- radare2 sandbox README (Debian): https://sources.debian.org/src/radare2/6.0.4%2Bdfsg-1/doc/sandbox/README.md
- CVE-2026-112077: https://www.suse.com/security/cve/CVE-2026-112077/ and https://bugzilla.redhat.com/show_bug.cgi?id=2562354
- rizin releases: https://api.github.com/repos/rizinorg/rizin/releases
- r2pipe on PyPI: https://pypi.org/pypi/r2pipe/json
- capa result document: https://raw.githubusercontent.com/mandiant/capa/master/capa/render/result_document.py
