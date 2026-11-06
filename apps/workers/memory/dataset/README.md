# Memory detection scenario set (M8 phase 3)

Labelled synthetic scenarios that measure the memory detectors
(`memory_worker/detections/`) by precision and recall (`requirement.txt` §14).

> **Caveat.** These scenarios were designed alongside the detectors. A precision and recall
> of 1.0 here shows that the detectors behave as specified on the cases they were written
> for. It says nothing about their real-world quality: real images hold JIT engines,
> security products, exited parents and vendor paths that no synthetic set covers. Real-world
> tuning is future work.

## What is here

| File | Role |
|---|---|
| `baselines.py` | Three benign baselines built as plain `memory.v1` records: a Windows 10 workstation (profile `full`, about 110 processes), a Windows Server domain controller (`triage`), a Debian server (`triage`). |
| `scenarios.py` | 21 scenarios: the 3 baselines, 16 positives (one baseline plus a few injected records each) and 2 benign near-misses. `build(name)` returns a `MemoryView`. |
| `labels.json` | Expected findings (`method`, `type`, `pid`, optionally `severity`) and IOCs per scenario. Hand-written and committed; frozen before the detectors were tuned. |
| `evaluate.py` | Runs every scenario through `detections.run` and prints TP / FP / FN, precision and recall per detection method, plus IOC recall. |

Nothing is generated into the repository: views are built in memory at test time. There
is no memory image here and nothing comes from a real host. External peers use the RFC 5737
documentation ranges, and the secrets in command lines and history are made up (listed in
`scenarios.SECRETS`).

## Running

```sh
# inside memory-worker-test (lane 3), or any Python 3.12 with py-jobs + py-worker-kit
python -m dataset.evaluate
pytest -q tests/unit/test_dataset_quality.py
```

`evaluate` exits 1 on any false positive or false negative. Phase 11 copies its table into
`plans/reports/memory-metric-YYMMDD.md`, together with the caveat above.

## Matching rules

- A finding matches a label on `(detection_method, type, pid)`, where `pid` is the
  finding's `pid` attribute (`null` for findings without one, such as the singleton count
  and service-path findings). When a label gives `severity`, that must match as well.
- Findings at `info` are ignored. Baselines and near-misses expect nothing above `info`,
  so any finding there counts as a false positive of its method.
- An IOC label matches on `(type, value)` and, when given, the IOC's first `source`. IOC
  labels list only what a scenario injects (recall). They never list everything the
  baseline yields.

## Near-misses covered

The baselines and the two near-miss scenarios hold the cases that fire on clean Windows
unless they are handled (RT21), plus a few more:

- Defender and Defender for Endpoint under `\ProgramData\...\Platform\` (service and process);
- `csrss.exe` / `wininit.exe` whose session `smss.exe` has gone, exited (still pool-scanned),
  or whose pid was reused by a later process;
- RWX regions without a PE header in browsers, PowerShell, Teams and `w3wp.exe`; executable
  but not writable regions; image-backed writable-copy regions;
- psscan-only processes that have exited (`userinit.exe`, installers);
- `LsaIso.exe` and `sihost.exe`, which are within two edits of core names;
- `.mui` / `.nls` data files missing from the loader lists, and a process's own image;
- driver object names (`\Driver\Tcpip`), driver-store and `\drivers\wd\` drivers;
- `lsass.exe` on a domain controller talking to internal clients;
- shell history with `curl` and no pipe, `nc -zv`, `python3 -c` without sockets, and
  `chmod +x` without a download.
