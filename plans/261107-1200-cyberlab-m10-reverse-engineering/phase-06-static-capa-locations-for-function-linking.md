---
phase: 6
title: "Static capa locations for function linking"
status: pending
priority: P2
effort: "8h"
dependencies: [1]
---

# Phase 6: Static capa locations for function linking (group B, 2e, lane 9)

## Overview
M3's capa records carry no addresses, so capabilities cannot be tied to functions. This phase fills the additive `static.v1` fields frozen in phase 1: the static worker's capa reducer emits the absolute addresses of each rule's matches and the base address capa used; the static ingest stores them in the two new columns; the static read model exposes them through `CapabilityLinkedOut` (RT6). Static jobs from before M10 keep empty locations.

**Owns:** in `apps/workers/static/static_worker/`: the capa reducer in `probe/reduce.py` (the `capa` probe mode), `engines/capa.py` (header field hand-off), the header assembly in `pipeline.py` (`capa_base_address`); in `apps/api/app/modules/static_analysis/`: the capability and sample parts of the static ingest and the `locations` part of `CapabilityLinkedOut` in the repository (`functions` is phase 8's); their tests (`apps/workers/static/tests/unit/test_capa_locations.py`, `apps/api/tests/integration/test_static_capa_locations.py`).

## Requirements
- **Reducer** (runs as the tool uid, as today): for each non-library rule kept, collect match addresses of type `absolute` only (capa's `frz.Address`; `relative`, `file`, `no_address` and dynamic kinds are dropped and counted), deduplicate, sort, keep at most 32 (`truncated["capability_locations"] = True` beyond), and emit them in `CapabilityRecord.locations`. Read `meta.analysis.base_address` (a capa `Address` object `{type, value}` in 10.x [I]: accept only `type: absolute`; if absent, use the PE ImageBase / lowest ELF PT_LOAD vaddr from the facts probe, recorded as `base_source`) and emit it as `StaticResultHeader.capa_base_address`. The RE join normalizes it to file virtual addresses with the file's preferred base (RT8); this phase records the capa base exactly as capa used it and tests what vivisect reports for a PE, an ELF PIE and an ELF non-PIE build (written into the phase notes for phase 7).
- **Root:** unchanged trust model; it only validates the new bounded fields.
- **Ingest:** `malware_capabilities.locations` (decimal strings in jsonb, the M3 numeric rule) and `malware_samples.capa_base_address`; absent fields store `[]` / NULL. An old-format stream (no fields) still ingests (test with a pre-M10 fixture).
- **Read model:** `CapabilityLinkedOut.locations` (strings, so JS never loses precision) on the existing capabilities route; **`CapabilityOut` stays unchanged** because it is also the item type of the static JSON report's `ReportCapabilities` (RT6). The static JSON report (`cyberlab.report.static.v1`) and the signed M6 snapshot (`cyberlab.report.v1`, `snapshot_sections.py`, `extra="forbid"` in the renderer) are **not** changed: a test proves both serialize byte-identically for an M3 fixture job before and after (the M8 RT10 lesson).
- **Rollout order** (RT18): `Strict` refuses unknown fields, so the **api / ingest image is rebuilt before the static image** (the parent's merge step 5); a test feeds a new-format stream to the ingest and an old-format stream to the new ingest; a static job that ran on an old image simply has no locations.
- **No re-run of old jobs** is automatic; the UI (phase 10) offers "re-run static analysis to link capabilities".

## Implementation Steps
1. Read the current reducer and a real capa JSON document from the M3 `injector` build (generated in the static dev image).
2. Implement the address collection; unit tests with hand-written capa JSON fragments (absolute, relative, file, no_address, > 32 matches, missing base).
3. Ingest and read model changes; integration test in lane 9.
4. One run of the static engine test on the mingw `injector` build in `static-worker-test` (`--heavy`, single run): locations present, inside `.text`.

## Success Criteria
- [ ] capa capabilities of the `injector` build carry absolute locations and the base address end to end (worker → ingest → API).
- [ ] Old streams and old rows behave exactly as before; the M3 static tests pass unchanged.

## Risk Assessment
- **capa JSON shape changes across versions:** the reducer reads only `rules.*.matches[*][0]` and `meta.analysis.base_address`, with fixture tests pinned to the bundled capa version.
- **Mixed image versions:** additive fields with defaults; the order api-first is required (an old ingest refuses `locations`); tested both ways.
