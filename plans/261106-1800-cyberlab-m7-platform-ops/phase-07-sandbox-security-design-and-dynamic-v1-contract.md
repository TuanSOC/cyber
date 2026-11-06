---
phase: 7
title: "Sandbox security design and dynamic v1 contract"
status: completed
priority: P1
effort: "10h"
dependencies: [1]
---

# Phase 7: Sandbox security design and dynamic v1 contract (group B, 2f, lane 7, unit only)

## Overview
The §7 dynamic analysis architecture and the §15 `docs/SANDBOX_SECURITY.md`, **as design and contract only**:
- the document covers every §7 requirement, the threat model of a sandbox, the integration pattern (re-using the M2 / M3 presigned and trusted-ingest pipeline) and the gating checklist that must pass before anyone enables it;
- the `dynamic.v1` contract is frozen as Pydantic models with fixtures;
- a gate test proves nothing is wired.

Dynamic analysis stays disabled.

**Owns:**
- `docs/SANDBOX_SECURITY.md`;
- `packages/py-jobs/src/cyberlab_jobs/dynamic.py` (the only py-jobs file outside phase 1; it is **not** exported from `__init__.py` in M7);
- `tests/fixtures/dynamic/**`;
- `tests/unit/test_dynamic_contract.py` and `tests/unit/test_dynamic_gate.py`.

## Requirements
- **`docs/SANDBOX_SECURITY.md`** sections:
  1. **Status:** "Designed in M7, **not enabled**." It may be enabled only when every item of section 9 passes on the target infrastructure and the parent records it in ROADMAP.
  2. **Scope and non-goals:** CAPE v2 as the engine (ROADMAP "Gated"). No execution on the app host, Docker Desktop / WSL2 or any shared API or analyzer container. No unrestricted internet.
  3. **Topology:**
     - a dedicated KVM host (bare metal or a nested-virt-capable VM on separate hardware);
     - three networks:
       - **management**: CAPE API ↔ `sandbox-bridge` only;
       - **analysis**: per-VM host-only bridges with nftables default-drop;
       - **sinkhole**: INetSim / FakeNet on the sandbox host;
     - no route from any VM network to the platform networks, the management network or the internet.

     Include a Mermaid diagram.
  4. **§7 requirement → control** (a table):

     | §7 requirement | Control |
     |---|---|
     | Disposable VMs | golden images and a per-job linked clone |
     | Snapshot rollback | revert before each job, destroy after; verified by hashing the disk after the revert |
     | Resource limits | vCPU, RAM, disk and I/O caps through libvirt; a per-job wall clock ≤ 300 s with a hard kill |
     | No host filesystem sharing | no virtio-fs or 9p shares |
     | No shared clipboard | no SPICE agent / vdagent; guest additions removed; no drag-and-drop; no USB redirection |
     | Controlled egress | route modes `none` (default) and `sinkhole`; `internet` / Tor / VPN forbidden and refused by the bridge |
     | Execution time limits | the per-job wall clock above |
     | Sample integrity | sha256 verified by the bridge before submit and by the guest agent before execution; mismatch → failed `integrity` |
     | Full audit | custody event `sent_to_sandbox`, the job audit, retained CAPE logs, and the route mode recorded in the result |
  5. **Integration pattern:**
     - a new untrusted `sandbox-bridge` worker on its own internal network with the broker and the management network only;
     - it receives `DynamicJobV1` (presigned GET for the exact evidence version, sha256, size, route mode, timeouts, presigned POST for results), submits to CAPE, polls, converts the CAPE report to `dynamic.v1` record lines and uploads them;
     - the trusted ingest validates the stream exactly like `static.v1` (caps, gzip-bomb limits, schema);
     - the bridge never holds DB or MinIO credentials;
     - the API never talks to CAPE.
  6. **Threat model:**
     - VM escape (hypervisor CVEs; patch cadence; no nested virt for guests);
     - sandbox detection and evasion (honest limits);
     - malicious CAPE output (parser in the bridge, an untrusted zone);
     - network egress abuse (DDoS, C2 through the sinkhole);
     - credential theft from guests (no real credentials in images);
     - data exfiltration through the result stream (caps, schema);
     - operator mistakes (the route mode default).
  7. **Data handling:**
     - dropped files are stored as hashes only in v1;
     - screenshots and PCAPs from the sandbox are deferred;
     - retention follows the M7 policy (`closed_case_days`).
  8. **Operations:** image building and patching, golden-image provenance, the kill switch (a broker ACL disable plus `DYNAMIC_ENABLED`), capacity.
  9. **Gating checklist (acceptance tests before enabling):**
     - escape-assumption tests (the guest cannot reach the host, management or platform IPs; no shared devices are visible);
     - egress tests per route mode (the external TCP, UDP, DNS and ICMP probes all fail; the sinkhole answers);
     - a snapshot-revert proof (a marker file is gone; the disk hash equals golden);
     - resource-limit tests (fork bomb, memory hog, disk fill → killed, the host unaffected);
     - integrity mismatch → refused;
     - audit completeness;
     - kill-switch drill;
     - a red-team review recorded.
  10. **Requirement traceability** to `requirement.txt` §7 and §13 "Sandbox escape assumptions".
- **`dynamic.py`** (Pydantic v2, the style of `static.v1`; never imported by the API or the workers in M7):
  - `DYNAMIC_SCHEMA = "dynamic.v1"`, `DYNAMIC_ENABLED: Final = False`.
  - `RouteMode = Literal["none", "sinkhole"]`.
  - `DynamicJobV1{job_id, org_id, evidence_sha256, evidence_bytes, sample_url, route: RouteMode, timeout_s ≤ 300, upload: PresignedPost, token, deadline}`.
  - The record lines (a discriminated union):
    - `process{pid, ppid, image, cmdline (BoundedText), start_ms, end_ms?}`;
    - `file{op, path, sha256?}`;
    - `registry{op, key, value_name?}`;
    - `network{proto, dst (sinkholed label), port, dns_query?, bytes, route}`;
    - `signature{name, severity, description (bounded), attack_ids[]}`;
    - `dropped{sha256, size, path}`.
  - `DynamicSummaryV1{status, error_code?, route, duration_ms, vm_image_digest, revert_verified: bool, counts}`.
  - **Caps:** lines ≤ 200 000; text fields bounded like `static.v1`. Unknown fields are forbidden.
- **Fixtures:** `tests/fixtures/dynamic/{benign_run.jsonl, hostile_run.jsonl}`. The hostile run carries a route of `internet` (must fail validation), an oversized cmdline, control characters and an extra field.
- **Gate test** (`test_dynamic_gate.py`):
  - `Analyzer` has no `dynamic` value;
  - no Celery queue or task name contains `dynamic`;
  - the broker entrypoint defines no `dynamic` / `sandbox` user;
  - no compose service named `*sandbox*` / `*dynamic*` in the rendered dev and prod configs (the parse step of the `check-*-env.mjs` pattern);
  - no route path contains `dynamic`;
  - `DYNAMIC_ENABLED is False`;
  - `cyberlab_jobs.__init__` does not export the module.

## Implementation Steps
1. Re-read `static.v1`, the M2 / M3 pipeline docs and THREAT_MODEL, so the document reuses their terms.
2. Write `dynamic.py`, the fixtures and `test_dynamic_contract.py` (round trip, caps, `internet` refused, extra field refused).
3. Write `test_dynamic_gate.py`.
4. Write `docs/SANDBOX_SECURITY.md`, with the requirement table and the checklist.
5. Run the lane-7 unit tests and `ruff` / `mypy` on the new files.

## Success Criteria
- [x] `docs/SANDBOX_SECURITY.md` exists, maps every §7 requirement to a control, and has the topology, threat model, integration pattern and gating checklist. — `docs/SANDBOX_SECURITY.md` (+215): §1 status "not enabled", §3 topology with a Mermaid diagram, §4 the §7 requirement → control table, §5 integration, §6 threat model, §9 gating checklist, §10 traceability (9316433).
- [x] `dynamic.v1` is frozen with fixtures; hostile input (internet route, oversize, extra fields) is refused. — `packages/py-jobs/src/cyberlab_jobs/dynamic.py` (+319); `tests/fixtures/dynamic/{benign_run,hostile_run}.jsonl` (14 / 12 lines); `unit/test_dynamic_contract.py::test_every_hostile_line_is_refused`, `test_hostile_fixture_covers_the_required_cases`, `test_no_route_but_none_and_sinkhole_exists`, `test_process_text_and_numbers_are_bounded`, `test_record_cap_is_200k_and_enforced`, `test_benign_fixture_round_trips_line_by_line` (9316433).
- [x] The gate test proves dynamic analysis is not wired into the enum, queues, broker, compose or routes. — `unit/test_dynamic_gate.py::test_analyzer_has_no_dynamic_value`, `test_no_shared_queue_or_task_name_is_dynamic`, `test_broker_defines_no_dynamic_or_sandbox_user`, `test_rendered_compose_has_no_dynamic_or_sandbox_service`, `test_no_route_path_contains_dynamic`, `test_dynamic_is_not_enabled`, `test_cyberlab_jobs_does_not_export_the_module`, `test_importing_the_api_and_every_worker_app_never_loads_the_module` (9316433).

## Risk Assessment
- **Design drift from CAPE reality:** keep the contract engine-neutral (CAPE specifics live only in the future bridge) and mark v1 as "subject to one revision when a bridge is built".
- **Over-design:** no VM, bridge or CAPE code in M7. Anything executable is out of scope.

## Implementation Notes (2026-11-07)
- **Commit:** 9316433 (phases 2–10 together). The empty `tests/fixtures/dynamic/` came from 980386a.
- **Lane 7 (unit only):** `scripts/lane-test.sh 7 …` on the two unit files, plus ruff and mypy on the new files. No container, VM, bridge or CAPE code (out of scope).
- **`docs/SANDBOX_SECURITY.md`** (+215), the ten sections of the plan:
  - status "Designed in M7, not enabled";
  - CAPE v2 scope and non-goals;
  - the KVM topology with management, analysis and sinkhole networks (Mermaid);
  - the §7 table;
  - the `sandbox-bridge` integration pattern (no DB or MinIO credentials; the API never talks to CAPE);
  - the threat model, data handling and operations (including the kill switch);
  - the gating checklist and the traceability to `requirement.txt` §7 / §13.

  ROADMAP "Gated" links it (phase 10).
- **`dynamic.py`** (Pydantic v2, on the py-jobs `Strict` base, so unknown fields are refused):
  - `DYNAMIC_SCHEMA = "dynamic.v1"`, `DYNAMIC_ENABLED: Final = False` and `RouteMode = Literal["none", "sinkhole"]`;
  - `DynamicJobV1` (`timeout_s ≤ 300`, presigned GET / POST, token, deadline);
  - a result header, the record union (process, file, registry, network, signature, dropped) and `DynamicSummaryV1` (`revert_verified`, `vm_image_digest`, counts);
  - `MAX_RECORD_LINES = 200 000`.
- **Deviation, additive:** `DynamicStreamCheck` / `DynamicStreamError` frame a whole stream the way the `static.v1` ingest does:
  - the stream must name this job and route;
  - the summary counts must match and nothing may follow the summary;
  - a spliced stream fails.

  It is still never imported by the API or the workers.
- **Integrity:** a hash mismatch is a failed run with code `integrity` (`test_integrity_failure_is_a_failed_run_with_code_integrity`).
- **Fixtures:**
  - `benign_run.jsonl` (14 lines) round-trips and passes the framing;
  - `hostile_run.jsonl` (12 lines) carries a route `internet`, an oversized cmdline, control characters (tab is the only one allowed) and an extra field, and every line is refused.
- **Gate test** (`test_dynamic_gate.py`, 11 tests):
  - no `Analyzer.dynamic`;
  - no shared queue, task or Celery route named `dynamic`;
  - no broker user and no compose service (source files and the rendered dev and prod configs) named `dynamic` or `sandbox`;
  - no route path contains `dynamic`;
  - `DYNAMIC_ENABLED is False`;
  - `cyberlab_jobs.__init__` does not export the module, and importing the API and every worker app never loads it.
- **Tests:** `unit/test_dynamic_contract.py` (17) and `unit/test_dynamic_gate.py` (11).
- **Contract stability:** v1 is engine-neutral and marked "subject to one revision when a bridge is built" (risk 1).
- **Gate:** nothing in this phase depends on a heavy step. The phase-11 full suite only re-runs these unit tests (pending gate).
- **Closure (2026-11-06):** These unit tests re-ran in the full API suite of gate run vp8; the gate passed in segments, not in one `pnpm verify:prod` run (see the plan's Closure).
