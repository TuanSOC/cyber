# Memory analyzer metrics (2026-11-07, partial)

M8 phase 11. **Synthetic caveat:** every number below comes from our own synthetic Linux images
(`apps/workers/memory/samples/memgen`, a fictional `6.1.0-cyberlab-synthetic` kernel described
by our own ISF) run through the real Volatility 2.28.2 in the sandboxed probe, and from the
hand-written scenario rows of the detector dataset. No third-party or real memory image was
run (parent decision); Volatility never parses a Windows kernel here (Windows is covered by
the replay engine and row fixtures only). The numbers show that the pipeline behaves as
specified, not its accuracy or speed on real machines.

**Partial:** this report was assembled from the runs of 2026-11-07 (the detector evaluation,
the phase-4 engine tests and one fuzz-lite run). The replayed latency collection
(`scripts/memory_metrics.py`: three replays of every synthetic image, per-plugin p50 / p95, and
the optional sparse 8 GiB scan) needs a heavy lane and was not run in this session (see
"Not measured"). Regenerate the full report with:

    pnpm memory:fuzz > fuzz.log            # heavy, alone (~30 min)
    pnpm memory:metrics -- --fuzz-log fuzz.log [--sparse]

## Detector precision / recall (phase 3 dataset, `python -m dataset.evaluate`)

| Detector | TP | FP | FN | Precision | Recall |
|---|---:|---:|---:|---:|---:|
| `heuristic:mem_correlated_indicators@1` | 1 | 0 | 0 | 1.00 | 1.00 |
| `heuristic:mem_hidden_process@1` | 2 | 0 | 0 | 1.00 | 1.00 |
| `heuristic:mem_injected_code@1` | 3 | 0 | 0 | 1.00 | 1.00 |
| `heuristic:mem_linux_shell_history@1` | 2 | 0 | 0 | 1.00 | 1.00 |
| `heuristic:mem_masquerade@1` | 3 | 0 | 0 | 1.00 | 1.00 |
| `heuristic:mem_process_lineage@1` | 2 | 0 | 0 | 1.00 | 1.00 |
| `heuristic:mem_service_path@1` | 1 | 0 | 0 | 1.00 | 1.00 |
| `heuristic:mem_suspicious_cmdline@1` | 3 | 0 | 0 | 1.00 | 1.00 |
| `heuristic:mem_unexpected_network@1` | 1 | 0 | 0 | 1.00 | 1.00 |
| `heuristic:mem_unlinked_module@1` | 1 | 0 | 0 | 1.00 | 1.00 |
| **all** | 19 | 0 | 0 | 1.00 | 1.00 |

IOC recall 8 / 8 over 21 scenarios. The scenarios were written alongside the detectors: 1.00
means "behaves as specified", not real-world quality.

## Parse success

### Phase-4 images (real engine, `tests/engine/test_synthetic_linux.py`)

Expected: a result for every image, the symbols-missing diagnostic for the changed banner, a
result after its ISF is imported. **11 / 11** as expected: `linux_benign` raw, LiME, ELF
(triage), `linux_orphan_and_dup` raw (full), `linux_wide` raw (process cap 500: pslist ok,
truncated), `symbols_missing` LiME (diagnostic) and raw (diagnostic, then a result after
`import` + reindex), plus a raw image cut inside `init_task` (a result with zero processes),
and the two API pipeline runs (`MEMORY_E2E=volatility3`: the benign LiME image through the
broker and the ingest, the changed banner ending `failed / symbols_missing`).

Per-plugin outcome on the synthetic kernel (by design: our ISF describes no VMAs, sockets,
fd tables or module list): `linux.pslist` ok, `linux.psaux` ok,
`linux.malware.check_syscall` ok (no rows), `linux.bash`, `linux.sockstat`, `linux.lsof`,
`linux.malware.malfind`, `linux.malware.hidden_modules` failed.

### Fuzz-lite (`MEMORY_FUZZ=1 pytest tests/fuzz`, seed 11)

75 runs, **75 / 75 ended cleanly** (a result, the diagnostic or a known job code; after every
run no tool-uid process was left, every probe's audit counts were zero, and the probes' peak
RSS was 675 MiB, below the 2.5 GiB `RLIMIT_AS`; the worker container never restarted). Total
1 747 s, slowest case 274 s.

| Outcome | Runs |
|---|---:|
| `result` | 43 |
| `os_undetermined` | 16 |
| `unsupported_memory_format` | 7 |
| `memory_parse_failed` | 6 |
| `identify_timeout` | 3 |

| Case family | Outcomes |
|---|---|
| truncate, corrupt_pages, cyclic_tasks, self_parent, huge_comm, huge_args, invalid_pointers, page_table_loop, lime_overlap | result × 4 each (Volatility's list walk stops at a loop or an unreadable entry) |
| elf_lying (PT_LOAD beyond the file / huge size) | result × 3 (two runs took 266 / 274 s: plugins ran to their 120 s fuzz timeout) |
| lime_lying, zero_length | os_undetermined × 4 each |
| lime_huge (LiME end near 2^64) | identify_timeout × 3 (identify never finishes; killed at the 120 s fuzz timeout) |
| 64 MiB random blobs behind the LiME, AVML, ELF, VMware, crash-dump (32 / 64), QEMU magics and plain random | os_undetermined × 8 (5.6–5.8 s each) |
| gzip, zip, xz, bzip2, zstd, 7z, rar | unsupported_memory_format × 7, refused by root before any probe (RT19) |
| hostile ISF in the store: deep nesting, wrong types, missing task_struct, self-containing struct, unknown references, not JSON | memory_parse_failed × 6 |
| hostile ISF: huge array, negative offsets, huge symbol address, 48 MiB oversize | result × 4 |

**Findings:** a LiME header whose range end is near 2^64 keeps the identify probe busy until
its timeout (`identify_timeout`, 600 s at the default limits), and an ELF core whose PT_LOAD
lies about its size can keep every plugin busy until the tool timeout: contained by the
timeouts as designed (THREAT_MODEL "Volatility on hostile images"), but a cheap root-side
sanity check of the container header against the file size would turn both into an early
`unsupported_memory_format` (follow-up, not done).

## Latency (real engine, triage, synthetic 16 MiB images; n = 1 per image)

Job wall time (identify + four plugin processes) from the engine test run:

| Image | Job (s) |
|---|---:|
| `linux_benign.raw` | 17.5–19.4 |
| `linux_benign.lime` | 21.1–23.8 |
| `linux_benign.elf` | 21.7–23.9 |
| `linux_orphan_and_dup.raw` (full profile, 8 plugins) | 31.9–36.1 |
| fuzz-lite median-type case (raw mutant, triage) | ~17–18 |
| API pipeline, both real-engine jobs incl. upload, broker and ingest | 36 s together |

Identify alone on a 64 MiB random blob: 5.6–5.8 s. Each plugin is a fresh Volatility process
(≈ 3–5 s of import, stacking and banner scan on these sizes, before the plugin itself).

## Not measured in this report

- Per-plugin p50 / p95 over three replays (`tests/fuzz/metrics_run.py`): needs a heavy lane;
  not run in this session because a lane consumer container could not be stopped (the stop was
  refused by the permission system).
- The probe-smoke scan of a sparse 8 GiB file (`--sparse`): not run (host RAM; same lane).
- Ingest time at every cap: no timed harness; the API suite's ingest tests cover every cap
  functionally (`test_memory_ingest.py`, `test_memory_reads.py`).
