---
phase: 6
title: Hardening e2e and docs
status: completed
priority: P1
effort: 10h
dependencies:
  - 5
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

## Implementation Notes (2026-11-04)
- **Fuzz-lite** (`tests/evaluation/test_fuzz_lite.py`): 50 mutated dataset captures, every run terminal within the budget with no tool process left. Outcomes: 23 results, 22 unparseable, 3 unsupported format, 2 zeek_failed.
  - It found a real crash: capinfos reported an absurd duration that broke the contract. Out-of-range values now become unknown.
- **Isolation tests** (uid, caps, environ, symlinks/FIFOs, escapees incl. non-dumpable, seccomp, TMPDIR, egress, DNS, broker ACL key confinement) were built in phases 1–2 and run in `pnpm test:workers`.
- **E2E** `apps/web/e2e/pcap.spec.ts`: register → case → upload the synthetic `mixed.pcap` → automatic analysis with the real ET Open snapshot → findings (beaconing, vertical port scan) and flows visible → no console errors (≈ 60 s).
  - `scripts/e2e.mjs` generates the dataset into `.e2e-data/` (gitignored) with the worker image; the e2e container mounts it at `/data`.
- **Verify:**
  - New step: worker reload, since Celery does not hot-reload; it force-recreates pcap-worker, pcap-worker-test, ingest-worker and ingest-beat.
  - New step: `pnpm test:workers`.
  - `verify --prod` also runs both e2e scenarios on the prod-like stack.
- **Docs:** new `docs/PCAP_ANALYSIS.md`. Updated:
  - ARCHITECTURE (analysis workers diagram, modules)
  - DATABASE (ERD + tables)
  - API (routes, refusals, error codes)
  - THREAT_MODEL (trust boundary 5, M2 STRIDE table, residual risks; nonce CSP, quotas and libmagic re-deferred)
  - TESTING (commands, coverage, M2 metrics)
  - DEPLOYMENT (env vars, analysis services, capacity, code reload)
  - ROADMAP (M2 done, deferrals)
  - README
