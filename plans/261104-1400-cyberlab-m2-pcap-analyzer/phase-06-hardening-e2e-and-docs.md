---
phase: 6
title: "Hardening e2e and docs"
status: pending
priority: P1
effort: "10h"
dependencies: [5]
---

# Phase 6: Hardening e2e and docs

## Overview
Prove the isolation claims, extend the gate, write PCAP docs, update M1 docs.

## Requirements
- Security tests (beyond the phase-1 isolation tests): tool timeout kills a hung process group
  (sleep shim); parser crash → failed job, next job still served; persistence attempt (tool
  leaves a background process) is killed before the next job; worker failure rate recorded [RT13].
- Parser-vuln posture (§13): document tool versions, update path (rebuild image), sandbox
  limits; fuzz-lite test: 50 random-mutation captures from the dataset → no hang, every job
  terminal within timeout.
- E2E: Playwright uploads generated `mixed.pcap` → waits for `succeeded` → asserts findings
  include beaconing + port scan and flows tab non-empty.
- verify: worker unit/integration tests + evaluation harness; prod override builds worker prod
  target.
- Docs: new `docs/PCAP_ANALYSIS.md` (pipeline, engines, schema `pcap.v1`, detectors +
  thresholds, metrics, limitations); update ARCHITECTURE, DATABASE, API, THREAT_MODEL
  (privilege separation, broker ACL + remaining trust, internal network, MinIO exposure to the
  parser network, rule supply chain, nonce CSP re-deferred to M3, libmagic re-deferred), TESTING (metrics), DEPLOYMENT
  (new services/env), ROADMAP (M2 done, OpenSearch deferred).

## Success Criteria
- [ ] `pnpm verify` + `pnpm verify:prod` green from fresh volumes.
- [ ] Metrics table in TESTING.md generated from `evaluation.json`.
- [ ] Reviewer pass with no open High findings.
