---
phase: 11
title: "Docs threat model and license notices"
status: pending
priority: P2
effort: "8h"
dependencies: [2, 3, 4, 5, 6, 7, 8, 9, 10]
---

# Phase 11: Docs, threat model and license notices (group C)

## Overview
Document M10 after the group-B merge: a new `docs/REVERSE_ENGINEERING.md`, the M10 sections of the existing docs, the threat model, and the license notices in the image and the docs. Numbers come from the phase-4 / phase-5 tables and, after phase 12, the metric report (a one-line follow-up edit is allowed there).

**Owns:** `docs/REVERSE_ENGINEERING.md` (new); the M10 sections or rows of `docs/{ARCHITECTURE,THREAT_MODEL,DATABASE,API,AI_ANALYST,MALWARE_ANALYSIS,DEPLOYMENT,TESTING,ROADMAP,PRD}.md` and `README.md`; `apps/workers/reverse/NOTICE.md`; the image's `/usr/share/doc/cyberlab-re/NOTICE` source file.

## Requirements
- **`docs/REVERSE_ENGINEERING.md`** (the `MALWARE_ANALYSIS.md` shape): when it runs (manual only, from a static `full` PE / ELF job), engines and versions (Ghidra 12.2 + PyGhidra 3.2 + JDK 25; radare2 6.2.6 if shipped), stages and limits, outputs and caps, decompile priority, capa linking (and the "re-run static" caveat), findings (methods, severities, wording), the AI `explain_function` task, the code viewer's safety rules, the synthetic sample set and quality tables with the caveat, limitations (x86 / x64 only, no managed code, minutes per sample, parser exposure, function-boundary disagreement with capa).
- **ARCHITECTURE:** a "Reverse engineering (M10)" section with the flow diagram, the stage-per-process design, the worker's network and volume, the platform-wide heavy-analysis cap (memory, disk, reverse; RT2).
- **THREAT_MODEL (M10):** threats and mitigations with their tests: a sample executed (never; no debugger / emulator); JVM / loader / decompiler exploit (uid 10010, seccomp AF_UNIX-only + no io_uring, rlimits including the decompiler's lowered `RLIMIT_AS`, cgroup, read-only rootfs, kill-by-uid; the child-process record is **detection, not prevention**, RT15; no W^X for the JIT, RT29); disk and memory exhaustion (the watchdog, the cgroup poller, RT5 / RT14); the PyGhidra launcher's helper subprocesses before the audit hook (root-controlled, recorded, RT1); network from the JVM without a SecurityManager (seccomp + internal network); file reads through library loading (off, explicit loader); hostile stage output (bounded readers, contract, cross-record validation); r2 command injection (fixed commands, the grep test); prompt injection through code (transforms, literal and identifier cuts, decompiler comments off, spotlighting, verifier; the 12 000-character exception as a residual); XSS / Trojan Source in the viewer (text rendering, escapes, homoglyph marking, escaped copy); forged links between capabilities and functions (trusted join from stored rows). Residuals: native parsers contained not prevented; integrity attacks on AI output detected not prevented; RE results (decompiled code included) visible org-wide (M1 RBAC, RT12); one org can occupy the heavy-analysis slot with sequential jobs.
- **DATABASE:** the migration, tables, checks, grants, the two M3 columns, the §11 mapping (RE results are analysis results of `reverse` jobs).
- **API:** the routes, codes, the `explain_function` task, string-encoded addresses.
- **AI_ANALYST:** the task row, the `G` / `Q` label kinds, the `Q.code` exception, the template rules, the eval numbers from phase 9 (offline).
- **MALWARE_ANALYSIS:** capa locations (`static.v1` additive fields) and the "Reverse engineer" action.
- **DEPLOYMENT:** image size (measured), RAM (4 GiB worker; the analyzer `mem_limit` table and `ANALYSIS_HEAVY_MAX_ACTIVE`, with when to raise it: a host that fits the sum of the heavy workers' limits; RT2), disk (`re_work` per job, wiped, `RE_MAX_WORK_BYTES`, the free-space check), the pinned artefacts and how to update them (re-run the spike checks), the `RE_QUICK_ENABLED` switch.
- **TESTING:** the sample set, ground truth, lanes (`re-worker-test`, `--heavy`), the quality and metric tables.
- **ROADMAP / PRD / README:** M10 row; "Later": ARM / AArch64 / MIPS, managed code, BSim / similarity, analyst renames and comments, RE search indexing, a job-level RE summary task, a call-graph view (RT24), a queue for heavy analyses (RT30), r2ghidra (if the no-go path shipped).
- **License notices** (`NOTICE.md`, image NOTICE; not legal advice): Ghidra Apache-2.0 with its NOTICE, the statement that the install was modified by deleting modules (the list), the GPL native helpers kept with their licenses; PyGhidra and JPype Apache-2.0; JDK GPLv2 + Classpath Exception; radare2 LGPL-3.0 (unmodified, separate process; no r2pipe, RT9); the note that redistributing the image to third parties brings source obligations for the GPL / LGPL parts (Ghidra source tag, Temurin source, radare2 source tarball, all pinned in `versions.json`), while running it for the user's own use brings none; unlike M8's VSL, nothing requires publishing CyberLab's adapter.

## Implementation Steps
1. Gather facts from the merged code, the spike notes and the quality tables.
2. Write `REVERSE_ENGINEERING.md`; update each doc section; NOTICE files.
3. Link check and a final read for verdict words and unverified claims (every number has a source: a test, a table or the research report).

## Success Criteria
- [ ] Every doc listed above has its M10 content; the threat model rows name their tests.
- [ ] The NOTICE files list every third-party component with its license and the trim statement.
- [ ] No doc presents synthetic numbers as real-world quality.

## Risk Assessment
- **Docs drifting from code:** written after the merge from the merged code; phase 12 may correct numbers with one-line edits.
