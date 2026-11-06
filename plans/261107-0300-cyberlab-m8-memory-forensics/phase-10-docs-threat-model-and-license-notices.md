---
phase: 10
title: "Docs threat model and license notices"
status: pending
priority: P2
effort: "8h"
dependencies: [2, 3, 4, 5, 6, 7, 8, 9]
---

# Phase 10: Docs, threat model and license notices (group C)

## Overview
Documents M8 as built, after the group-B merge. Before editing, this phase re-checks every claim against the merged code, with the M7 phase-10 discipline: no feature is documented as done without its test.

**Owns:**
- `docs/MEMORY_FORENSICS.md` (new);
- the M8 sections of `docs/{ARCHITECTURE,THREAT_MODEL,DATABASE,API,DEPLOYMENT,TESTING,ROADMAP,PRD}.md` and `README.md`;
- `apps/workers/memory/NOTICE.md`;
- `apps/workers/memory/samples/README.md`, `dataset/README.md` (if phases 3 and 4 left them thin).

## Requirements
- **`docs/MEMORY_FORENSICS.md`** (the `MALWARE_ANALYSIS.md` structure):
  - when it runs: always manual, never auto;
  - the upload option and size limit;
  - the profiles and the plugin table with the 2.28.2 names;
  - the never-run list and why (credentials, envars, dumps, tar-slip), and the red-team cuts (`windows.handles`, YARA over memory, RT8 / RT9);
  - **real-engine coverage**: Linux real-engine tested on the synthetic image (or the recorded no-go), Windows "replay-tested, not validated on a real image in CI" (RT4);
  - the pipeline (Mermaid sequence);
  - isolation (the M2 table plus the per-plugin process, uid 10006, AF_UNIX-only seccomp without io_uring, the audit hook, the refusing file handler, offline library mode, the symbol path list, read-only symbols, `HOME` / config dirs);
  - symbols: the store, the diagnostic result, and the operator workflow with examples;
  - result contract `memory.v1`;
  - findings (the detector table, never verdicts, severity caps);
  - sensitivity (TLP:RED from a `kind=memory` upload, release, secret masking on shared surfaces, reports and the `omissions` count, AI / TI);
  - the synthetic scenario metrics table with the caveat;
  - the synthetic image go / no-go and the probe-smoke result; no third-party memory image is used (parent decision);
  - limitations (macOS, ARM64, hiberfil, `.vmss`, compressed uploads, no extraction, symbol coverage, Volatility robustness, single-request upload).
- **ARCHITECTURE:**
  - a "Memory forensics (M8)" section with the flowchart (worker on `analysis`; `memory-symbols` on its own `symbols_egress`);
  - the networks table rows;
  - the analyzer list.
- **THREAT_MODEL "M8: memory forensics"**, threats → mitigation → tested by:
  - a parser exploit in Volatility (sandbox, per-plugin process);
  - a DoS image (timeouts, `RLIMIT_AS`, caps, fuzz-lite);
  - symbol poisoning (a read-only store, manifest hashes, operator-only import, `jsonschema`);
  - a hostile GUID or banner relayed to the operator (strict validation, suffix-allow-listed hosts, no command ever embeds the banner);
  - network at analysis time (offline constants, AF_UNIX-only seccomp, the audit hook, the network);
  - pre-restriction exposure (TLP:RED at `kind=memory` upload, no auto-run);
  - plugin code loading (read-only site-packages, no `-p`, no config);
  - secret disclosure (TLP:RED default, no credential plugins, AI / TI exclusion, report TLP guard);
  - forged results (identity check, trailer, caps).
  - Residuals:
    - org-wide readers see command lines and bash history (secrets masked only on the shared surfaces);
    - Windows not validated on a real image in CI;
    - the compromised-root-process residual from M2;
    - the VSL publishing obligation;
    - symbol coverage;
    - single-request upload;
    - Microsoft symbol server terms and redistribution unverified.
- **DATABASE:** 0015 (tables, checks, grants, RLS); the §11 mapping updated (`memory_findings` → `analysis_findings` of memory jobs; `forensic_artifacts` → `memory_artifacts`).
- **API:** the memory routes, the `kind=memory` upload, the analysis request fields, the sensitivity routes, the error codes.
- **DEPLOYMENT:**
  - the memory worker and its sizing (3 GiB RAM; disk ≈ 3× the image size in flight: spool, MinIO, worker copy);
  - `MEMORY_MAX_BYTES` and `CADDY_EVIDENCE_MAX`;
  - the quota advice;
  - the **symbols runbook** (`memory:symbols` commands, the Linux dwarf2json workflow done elsewhere, `verify` after restores);
  - **backups:** the symbol volume is not in the M7 backup; it is rebuildable from the manifest, so keep a copy of `manifest.json`;
  - upload limits: Caddy `read_body 30m` (≥ 4.6 MB/s for 8 GiB), the 16 GiB ceiling, disk footprint and Docker Desktop disk growth (RT14);
  - the `fetch-windows` redirect-suffix list and what to do when a fetch is refused (RT11);
  - an **operator smoke procedure** for the first real image (manual, never automatic; RT4);
  - the egress footprint of `memory-symbols` (`symbols_egress` only, msdl and its CDN).
- **TESTING:**
  - the M8 suites and lanes (`--service memory-worker-test`, `--heavy`, lane 8);
  - the replay engine's test-only status;
  - the metric numbers from `plans/reports/memory-metric-YYMMDD.md` (phase 11 fills in the final figures);
  - the synthetic-numbers caveat.
- **ROADMAP:**
  - the M8 row;
  - "Later": direct multipart upload with server-side re-hash, a synthetic Windows image, hiberfil / `.vmss`, macOS / ARM64 when upstream supports them, process / file extraction behind an explicit legal gate, per-case access control for sensitive evidence, combining cheap plugins per process, memory-specific AI tasks, memory-specific YARA rules, `windows.handles` with paging;
  - the VSL publishing decision.
- **PRD and README:** memory forensics as an implemented module with its limits; "Memory Analysis" no longer "planned".
- **License notices:**
  - `apps/workers/memory/NOTICE.md`:
    - volatility3 2.28.2 is used unmodified under the Volatility Software License v1.0 (link, and where the license text sits in the image);
    - the code in this directory is an "Addition" in the VSL's sense (software that executes Volatility and parses its results);
    - it must be published under the VSL if made available to others, by copies or over the Internet;
    - the dependency licenses: pefile MIT, capstone BSD-3, jsonschema MIT;
    - leechcorepyc (GPLv3), pycryptodome, pysmb and the YARA engines are deliberately absent;
    - the VSL also counts "content or materials, including training materials, that contain any portion of the software" as Additions: the repository's docs link to upstream and never paste Volatility source (RT27).
  - README "Third-party software and licenses" gains the same summary and the open user decision (the repository itself has no license file yet).
  - Mark every legal statement "not legal advice".

## Implementation Steps
1. Read the merged code and phase notes; list each claim to verify.
2. Write `MEMORY_FORENSICS.md`, then the cross-doc sections.
3. NOTICE and README license section.
4. Link check (relative links), a grep for the stale "planned" wording on Memory Analysis, and a grep that no doc pastes Volatility source (RT27).

## Success Criteria
- [ ] `docs/MEMORY_FORENSICS.md` exists and every statement in it maps to code or a test.
- [ ] THREAT_MODEL has the M8 section with residuals.
- [ ] DATABASE §11 mapping no longer says "not implemented" for memory.
- [ ] The VSL notice and the publishing decision are recorded in NOTICE, README and ROADMAP.

## Risk Assessment
- **Over-claiming:** "production-ready" is never used. The synthetic caveat and the symbol-coverage limits are stated prominently (§16).
- **Legal wording:** factual, citing the license text and the research report; no legal conclusions beyond "not legal advice".
