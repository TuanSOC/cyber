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
