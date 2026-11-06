---
phase: 4
title: "Synthetic memory image generator and engine smoke"
status: pending
priority: P2
effort: "18h"
dependencies: []
---

# Phase 4: Synthetic memory image generator and engine smoke (spike: group A′, parallel with phase 1; rest: group B, 2c, lane 4, `--heavy`)

## Overview
A real end-to-end proof that does not depend on downloading anyone's memory image: a generator that writes a **tiny synthetic Linux x86-64 memory image** together with **our own minimal ISF** that matches it, so that the real Volatility 2.28.2 stacks the layers, matches the banner and runs `linux.pslist` offline inside the worker. No public project does this (research §8), so the phase starts with a **10 h spike and a recorded go / no-go**.

**Red-team changes (RT4, RT6, RT15):** with the reference corpus dropped (parent decision: no third-party memory image), this image is the only place the real Volatility parses kernel structures in CI. The **spike therefore runs first, in parallel with phase 1**: its own worktree `..\cyber-wt\m8-spike` from the M7 merge, on host Python in a throwaway `uv` venv (`volatility3==2.28.2`, `jsonschema`) in the scratch dir, no containers and no lane slot; it writes only `samples/memgen/**` and its notes, which phase 1 leaves untouched. The go / no-go is recorded and sent to the parent **before group B starts**. The rest of the phase (scenarios, wrappers, worker tests) runs in group B on lane 4 after the phase-1 commit. Engine tests build their symbol store in a temp dir (`MEMORY_SYMBOLS_DIR`), never in the shared `memory_symbols_test` volume, and the image in the per-container tmpfs `/work`.

Why Linux: Windows discovery needs a kernel PE with a PDB CodeView record, the DTB and kernel-base heuristics and a large type surface. Linux needs a banner string, page tables reachable from `init_top_pgt` / `swapper_pg_dir`, and an `init_task` list, all described by an ISF we write ourselves (research §8 [I]). A synthetic Windows image is out of scope ("Later").

**Owns:**
- `apps/workers/memory/samples/memgen/**` (generator, scenario definitions, LiME and ELF-core wrappers, mutation helpers for fuzz-lite);
- `samples/isf/**` (the generator also writes the ISF; only the generator is committed, the output is built at test time);
- `tests/unit/test_memgen.py`, `tests/engine/test_synthetic_linux.py`.

## Requirements
- **Spike (first 10 h):**
  1. Read the 2.28.2 Linux automagic (`automagic/linux.py`: banner scan, `LinuxIntelStacker`, KASLR shift and DTB derivation, VMCOREINFO use) and `linux.pslist` (the `task_struct` fields it reads: `tasks`, `pid`, `tgid`, `comm`, `parent` / `real_parent`, `mm`, `cred`, start time, flags). List the minimal type and symbol set in the phase notes.
  2. Generate a raw image (16 MiB) with:
     - a `linux_banner` string (`Linux version 6.1.0-cyberlab-synthetic … #1 SMP …`);
     - x86-64 4-level page tables that map the kernel virtual range used by the ISF symbols onto the physical pages;
     - `init_task` and N `task_struct`s on a circular `tasks` list.
  3. Generate the ISF (`cyberlab-synthetic-6.1.0.json.xz`): metadata with the banner and the producer `cyberlab-memgen`, the base types, the minimal user types, and the symbols (`init_task`, `linux_banner`, `init_top_pgt` / `swapper_pg_dir`, plus whatever the stacker needs). It must validate against Volatility's schema with `jsonschema` installed.
  4. **Go** when `linux.pslist` returns the generated processes offline (`constants.OFFLINE = True`) with only this ISF in a symbol dir, on host Python. Record the result, the time spent and the blockers in the phase notes, and tell the parent before group B starts. (The in-worker confirmation is the first group-B step.)
- **After go** (remaining 8 h):
  - Scenarios:
    - `linux_benign` (about 30 processes in a plausible tree);
    - `linux_orphan_and_dup` (a process with a missing parent, a duplicate name);
    - `linux_wide` (2 000 processes, for the cap and tree tests).
  - Wrappers: raw, **LiME** (a valid header per range) and **ELF64 core** (PT_LOAD per range), all three of which must stack.
  - Stretch, only if cheap: `linux.psaux` (an `mm` with `arg_start` / `arg_end` mapped in a user page table) and `linux.sockstat` (a minimal socket set). If they are not done, the plugins report `failed` / `unsupported` on the synthetic image, and the test asserts exactly that.
  - **Symbols-missing variant:** the same image with a changed banner and no matching ISF. Identify must report `LinuxBanner{…}` and the pipeline the diagnostic result.
  - **Fuzz helpers** (used by phase 11): truncation, random page corruption, a cyclic `tasks` list, a self-parent loop, a huge `comm`, invalid pointers, a LiME header with overlapping or lying ranges.
  - `test_synthetic_linux.py` (`--heavy`): generate into the test tmpfs work dir, build a temp symbol store with the ISF (direct copy plus a manifest entry and a reindex at the store's mount path; after the merge, phase 5's `import`), run the real pipeline, and assert processes, the tree, plugin statuses and the header `engine: volatility3`.
- **No-go:**
  - The phase stops at the spike. The notes record why.
  - The replay engine (phase 2) becomes the e2e engine in the test profile.
  - Phase 11's fuzz-lite uses raw / LiME header mutations only (they still exercise the stacker).
  - The plan's "Real engine" criterion is then satisfied by the recorded no-go plus phase 2's probe smoke; the real engine then never parses a kernel structure in CI. The parent records this in ROADMAP and TESTING.
- **Licensing:** the generator, the scenarios and the generated ISF are our own work. They contain no Volatility code and no data from any third-party image.
- **Size:** every generated image is ≤ 32 MiB and built in the test work volume, never on the host disk and never committed.

## Implementation Steps
1. Spike steps 1–4 with the time box, during phase 1, on host Python (RT15); record go / no-go and tell the parent before group B starts.
2. Go: scenarios, wrappers, symbols-missing variant, fuzz helpers.
3. `test_memgen.py` (layout, wrappers, determinism with a seed) on lane 4 without `--heavy`; `test_synthetic_linux.py` with `--heavy`.
4. `ruff` / `mypy` on own files.

## Success Criteria
- [ ] Go / no-go recorded with evidence before group B starts.
- [ ] (Go) Volatility 2.28.2 runs `linux.pslist` on the synthetic image offline in the worker, for raw, LiME and ELF-core wrappers, and the pipeline produces a valid `memory.v1`.
- [ ] (Go) The changed-banner variant gives `symbols_missing` with the banner.
- [ ] Fuzz helpers exist and are deterministic (seeded).

## Risk Assessment
- **Feasibility:** the Linux automagic may need more of the kernel than a minimal ISF supplies (KASLR detection, VMCOREINFO). The time box and the fallback bound the loss to 10 h.
- **Fidelity:** a synthetic image proves the plumbing, not Volatility's correctness on real kernels. Nothing in CI covers that (no third-party images, parent decision); the docs say so and DEPLOYMENT gives the operator a manual smoke procedure on their own evidence.
- **Host-Python spike vs the worker image:** the spike runs the same pinned Volatility on Windows host Python; the first group-B step repeats the go case inside the worker, and a difference is reported to the parent.

## Implementation notes (2026-11-07, main tree)

**Go / no-go: GO**, first attempt (about 2 h including reading the 2.28.2 sources; no blocker). The spike ran inside the existing `cyberlab/memory-worker:dev` image (`docker run --network none`, the pinned Volatility 2.28.2 already installed there; no host venv, nothing downloaded): `vol --offline -s <dir with only our ISF> -f <image> linux.pslist` listed every generated process on the raw, LiME and ELF-core wrappers, and `linux.psaux` printed the argv (kernel threads as `[comm]`). The worker-side confirmation is `tests/engine/test_synthetic_linux.py` (below).

**What Volatility needs (read from `automagic/linux.py`, `symbols/linux/__init__.py`, `extensions/__init__.py`, `plugins/linux/{pslist,psaux}.py`):**
- `LinuxIntelStacker`: the ISF's `linux_banner.constant_data` (raw bytes, `\n\0` included) found in the physical layer; `find_aslr` scans for `swapper/0` + NULs, reads `pid` (0), `active_mm`, `tasks.next/prev` and `files` (= `&init_files` gives the virtual shift); the physical shift is the hit minus `init_task - 0xffffffff80000000`; both 0 here. DTB = `init_top_pgt` translated the same way (must not be 0). The VMCOREINFO stacker finds no note and steps aside.
- `LinuxKernelIntermedSymbols` raises unless these types exist (any layout): file, list_head, hlist_head, mm_struct, super_block, task_struct, vm_area_struct, qstr, dentry, fs_struct, files_struct, kobject, cred, inode, idr, address_space, page, vfsmount, net, socket, sock, inet_sock, unix_sock.
- `linux.pslist`: `init_task.tasks` walked both ways, init_task itself never listed; per task `pid`, `tgid`, `comm[16]`, `real_parent->tgid`, `flags` (PF_KTHREAD), `mm` == `active_mm` for user tasks (else the task is invalid), `cred->{uid,gid,euid,egid}.val` (`kuid_t` / `kgid_t`). Creation time needs `tk_core` (absent: `-`, suppressed by the plugin).
- `linux.psaux`: `mm->pgd` (a process layer through the parent's translation), `mm->arg_start` / `arg_end`.
- Symbols in our ISF: `linux_banner`, `init_task`, `init_mm`, `init_files`, `init_cred`, `init_top_pgt`; base types incl. `pointer`; metadata `format 6.2.0`, producer `cyberlab-memgen 0.1.0`, `linux: {symbols: [], types: []}`. It validates against the installed `schema-6.2.0.json` (Draft 2020-12) and phase 5's real `import` accepts it.

**As built** (`apps/workers/memory/samples/memgen/`, stdlib only, our own work, no Volatility code, no third-party data):
- `kernel.py`: struct layouts, the ISF builder (`isf`, `isf_xz`: deterministic bytes), the banner (`Linux version 6.1.0-cyberlab-synthetic (...) #1 SMP PREEMPT_DYNAMIC ...`) and the changed-banner variant (`6.1.0-cyberlab-unknown`).
- `image.py`: a 16 MiB flat physical map: 4-level page tables (kernel half with 2 MiB pages at `0xffffffff80000000 + phys`; one shared user address space mapping the argv region at `0x7ffd00000000`), banner, `init_task` + one `task_struct` per process on the circular list in scenario order, mm / cred / argv, seeded noise as free memory; a ppid outside the scenario gets an *exited* parent (a `task_struct` off the list). `MemoryImage.set(pid, member, value)` patches a member.
- `scenarios.py`: `linux_benign` (33 processes: kthreads under kthreadd, systemd services, sshd session, nginx / postgres workers), `linux_orphan_and_dup` (+ a child of exited pid 4242, + a second `systemd` as uid 1000), `linux_wide` (2 000), `symbols_missing` (benign with the unknown banner).
- `wrappers.py`: raw, LiME (32-byte header per range; the 640 KiB..1 MiB hole left out) and ELF64 core (`ET_CORE`, one `PT_LOAD` per range, `p_paddr` = physical). All three stack (`raw`, `LimeLayer`, `Elf64Layer` in the image record).
- `mutate.py` (fuzz helpers, seeded per mutant, lazy): truncate, zero-length, corrupt pages, cyclic `tasks`, self-parent, huge (non-NUL, non-ASCII) `comm`, huge argv, invalid pointers, page-table loop, LiME lying / overlapping / huge ranges, ELF `PT_LOAD` beyond the file. `mutants(seed, count)` round-robins the 13 families.
- `python -m samples.memgen --scenario S --format raw|lime|elf --out F [--isf-out F]`. Images are ≤ 32 MiB (16 MiB raw), built at test time, never committed.

**Verified in Docker (lane 4):**
- `tests/unit/test_memgen.py` (16 tests, also green on host Python with the schema test skipped): every ISF symbol translates through `init_top_pgt` with our own page walk, the `find_aslr` facts on `swapper/0`, the circular list order, parent / cred / mm / argv per process, scenarios, layout refusals, ISF against Volatility's schema, LiME / ELF hold the same bytes, determinism (images, ISF, mutants), the seed changes only free memory, every fuzz family damages what it names, the CLI.
- `tests/engine/test_synthetic_linux.py` (6 tests, `--heavy`, ~3 min): the ISF imported into a temp store by phase 5's real `import` and indexed by the real indexer at the store's own path; the real pipeline (sandboxed probe, offline) on `linux_benign` raw / LiME / ELF (triage: 19–24 s each) gives `engine: volatility3`, `symbols.resolved` with the manifest's sha256, exactly the scenario's processes (pid, ppid, name) with psaux cmdlines, zero audit events, no `isf_*` / `probe_offline_unverified` engine error. Plugin statuses on the synthetic kernel, asserted exactly: `linux.pslist` ok, `linux.psaux` ok, `linux.malware.check_syscall` ok with no row (no `sys_call_table`), `linux.bash`, `linux.sockstat`, `linux.lsof`, `linux.malware.malfind`, `linux.malware.hidden_modules` failed (`plugin_failed`: our ISF describes no VMAs, sockets, fd tables or module list). `linux_orphan_and_dup` full profile: 36 s, ppid 4242 not listed, two `systemd`. `linux_wide` with `max_processes = 500`: pslist ok, truncated, 500 rows. `symbols_missing` (LiME): the diagnostic stream with `LinuxBanner{6.1.0-cyberlab-unknown ...}`, only identify ran. A raw image cut inside `init_task` ends as a result with zero processes (pslist ok, 0 rows: the list walk stops at the first unreadable entry), never a crash, no tool process left.
- ruff / ruff format / `mypy memory_worker tests samples` green (`samples` added to the memory mypy step of `pnpm test:workers`).

**Not done (stretch):** `linux.sockstat` on the synthetic image (it fails, asserted); creation times (would need `tk_core`).
