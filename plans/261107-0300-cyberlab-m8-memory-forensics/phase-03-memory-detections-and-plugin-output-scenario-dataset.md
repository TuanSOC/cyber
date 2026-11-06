---
phase: 3
title: "Memory detections and plugin output scenario dataset"
status: pending
priority: P2
effort: "15h"
dependencies: [1]
---

# Phase 3: Memory detections and plugin output scenario dataset (group B, 2b, lane 3)

## Overview
Deterministic triage heuristics over the **normalized** memory records (never over raw plugin output), plus the labelled synthetic scenario set that measures their precision and recall (`requirement.txt` §14). Same rules as M2 / M3:
- findings describe what was observed, with the measured values; never verdicts ("malicious", "infected" are rejected by a test);
- heuristics cap at `medium`; M8 has no signature method (memory YARA is cut, RT8), so nothing reaches `high`;
- every finding names `detection_method` (`heuristic:<name>@1`), severity, confidence and evidence refs (pids, offsets).

The detectors are pure Python over the phase-1 `MemoryView`, so this phase needs no Volatility, no image and no symbols. The engine (phase 2) calls `detections.run(view, limits)`.

**Owns:**
- `apps/workers/memory/memory_worker/detections/**` (after the phase-1 stub `run`), including the secret masker `detections/mask.py` (RT13);
- `apps/workers/memory/dataset/**` (scenario generator, labels, `evaluate.py`, README);
- `apps/workers/memory/tests/unit/test_detections_*.py`, `test_mask.py`, `test_dataset_quality.py`, `test_finding_wording.py`.

## Requirements
- **Detectors (version 1).** Windows unless noted. Every threshold is a named constant.

  | Method | Fires on | Max severity |
  |---|---|---|
  | `heuristic:mem_hidden_process@1` | a process found by `psscan` but not by `pslist`, **with no exit time** and threads > 0 (exited processes and pool remnants are not "hidden") | medium |
  | `heuristic:mem_injected_code@1` | a `malfind` region that is private, executable and writable; `medium` when it starts with an `MZ` header or a PE header at an in-bounds `e_lfanew`, `low` otherwise; regions in known JIT hosts (a constant list, e.g. .NET and browser processes) without a PE header are skipped. Titles describe the observation ("private executable memory region with a PE header"), never "injected code" (RT21) | medium |
  | `heuristic:mem_process_lineage@1` | core-process rules: `smss.exe` not a child of `System` (pid 4); `wininit.exe` / `csrss.exe` whose parent is present and is not `smss.exe` (a **missing** parent never fires: the session `smss.exe` instances exit normally, RT21); `services.exe` not a child of `wininit.exe`; `lsass.exe` not a child of `wininit.exe`; `svchost.exe` not a child of `services.exe`; more than one `lsass.exe`, `services.exe` or `wininit.exe` alive | medium |
  | `heuristic:mem_masquerade@1` | a name at edit distance 1–2 from a core process name (`scvhost.exe`, `lsas.exe`, `svch0st.exe`), or a core name whose image path is outside `\Windows\System32\` / `\SysWOW64\` | medium |
  | `heuristic:mem_suspicious_cmdline@1` | command-line patterns: PowerShell `-enc` / `-EncodedCommand`, `-nop -w hidden`, `IEX` with a download cradle; `certutil -urlcache`, `bitsadmin /transfer`, `mshta http`, `rundll32 javascript:`, `regsvr32 /i:http`, `wmic process call create` | medium (`low` for a single weak pattern) |
  | `heuristic:mem_unlinked_module@1` (profile `full`) | an `ldrmodules` entry missing from all three loader lists, with a mapped path; the process's own image is excluded | medium |
  | `heuristic:mem_service_path@1` | a service binary under a user-writable path (`\Users\`, `\Temp\`, `\ProgramData\`, `\AppData\`), or a kernel driver outside `\System32\drivers\`; a constant exclusion list covers the vendor platform paths every clean image has (`\ProgramData\Microsoft\Windows Defender\Platform\`, RT21) | low |
  | `heuristic:mem_unexpected_network@1` | an established connection to an external address owned by a process that normally has none (a constant list: `lsass.exe`, `notepad.exe`, `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, …) | medium |
  | `heuristic:mem_linux_shell_history@1` (Linux) | `bash` history entries with download-and-execute or reverse-shell patterns (`curl … \| sh`, `wget … && chmod +x`, `/dev/tcp/`, `nc -e`, `python -c … socket`) | medium |

- **Combinations, not single facts:** a process with two or more of hidden / injected / lineage / masquerade / unexpected network gets one extra `heuristic:mem_correlated_indicators@1` finding (medium, confidence high) that refs the others; it never raises their severity.
- **Secret masking** (`detections/mask.py`, RT13): every text quoted from a command line or a bash history line into a finding (title, description, evidence), an IOC's context or a timeline title passes a deterministic masker first: `password=` / `pwd=` / `passwd=` values, `-p<value>` after `mysql` / `sshpass` style tools, `/user:<u> <password>` (`net use`), `Authorization: Bearer …`, `--token` / `--secret` / `--api-key` values, AWS access-key ids and secret-key shapes, `-----BEGIN … PRIVATE KEY-----`. A masked value keeps its first 2 characters and its length (`P@********(10)`). Raw text stays in the records (`memory_processes.cmdline`, `memory_artifacts`), never in these shared surfaces (M7 search indexes finding titles and descriptions). Unit tests per pattern plus a benign-cmdline corpus that must stay unchanged.
- **IOCs** (observables only): remote addresses of connections (internal ones kept and marked non-TI-eligible by the M6 normalizer at ingest), URLs, domains and IPs found in command lines and bash history, through the shared extractor `cyberlab_worker.iocs` (lifted from the static worker in phase 1). Each IOC records first / last seen (connection `created` or process create time when known), count and source (`connection`, `cmdline`, `bash`).
- **Timeline:** image system time; process creates and exits (at most 2 000, oldest first); connection creation times (at most 2 000); findings; `limits.max_timeline` (5 000) overall, `truncated` beyond (RT9).
- **Bounds:** detector state capped (`MAX_DETECTOR_KEYS` 50 000, `truncated.detector_state`); at most `limits.max_findings`.
- **Scenario dataset** (`dataset/`; generated at test time, never committed as output):
  - `scenarios.py` builds `MemoryView`s in the exact phase-1 record shapes, with realistic benign baselines: a Windows 10 workstation (about 120 processes, browser, Office, .NET JIT host with RWX regions), a Windows Server with many services, and a Linux server.
  - Positive scenarios, each injected into a benign baseline: hidden process, injected PE, injected shellcode (no MZ), lsass with a wrong parent, two lsass, `scvhost.exe`, core name from `\Users\Public\`, encoded PowerShell, certutil download, unlinked DLL, service in `\ProgramData\` (outside the exclusion list), lsass with an external connection, `curl | sh` in bash history, a command line with a password (masked in the finding), and one process combining three indicators.
  - Benign near-misses: Defender under `\ProgramData\…\Platform\`, `wininit.exe` / `csrss.exe` with an exited parent.
  - `labels.json`: the expected (method, finding type, pid) per scenario; benign baselines expect nothing above `info`.
  - `evaluate.py` runs every scenario through `detections.run` and prints TP / FP / FN, precision and recall per detector, plus IOC recall; phase 11 writes the table into `plans/reports/memory-metric-YYMMDD.md`.
- **Caveat** written into the README and later into the docs: synthetic numbers on scenarios designed alongside the detectors show that the detectors behave as specified, not real-world quality (the M2 / M3 wording).

## Implementation Steps
1. Read the M3 detectors (`static_worker/detections/**`) and the phase-1 `MemoryView`, record models and `cyberlab_worker.iocs`.
2. One module per detector with its constants; the combination pass; IOC and timeline builders.
3. The scenario generator, labels and evaluation harness.
4. Wording test (no verdict words in templates), severity caps test, per-detector unit tests (positive, benign near-miss, boundary values).
5. Lane 3: `scripts/lane-test.sh 3 --service memory-worker-test pytest -q tests/unit/test_detections_*.py tests/unit/test_dataset_quality.py tests/unit/test_finding_wording.py` (no `--heavy`: no image is read), plus `ruff` / `mypy`.

## Success Criteria
- [ ] Every positive scenario produces its labelled finding and every benign baseline nothing above `info` (precision and recall 1.0 on the set, recorded with the caveat).
- [ ] No heuristic exceeds `medium`.
- [ ] No finding, IOC context or timeline title of the scenario set contains an unmasked secret from its command lines or bash history.
- [ ] No template contains a verdict word.
- [ ] Detector state and finding caps set `truncated` flags instead of failing.

## Risk Assessment
- **False positives on real systems:** malfind and lineage rules are noisy (JIT, security products, exited parents). Mitigated by the skips above, `low` for weak signals and never-a-verdict wording; real-world tuning is future work.
- **Overfitting to the synthetic set:** the caveat; labels are frozen before the detectors are tuned (commit order recorded in the phase notes).
- **Plugin column drift:** the detectors read only normalized records, so a Volatility column rename is absorbed by phase 2's normalizer.
