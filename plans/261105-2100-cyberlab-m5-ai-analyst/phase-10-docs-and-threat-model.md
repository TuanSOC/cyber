---
phase: 10
title: "Docs and threat model"
status: completed
priority: P2
effort: "5h"
dependencies: [2, 3, 4, 5, 6, 7]
---

# Phase 10: Docs and threat model (group C, 3c)

## Overview
Write the M5 documentation from the merged group-B implementation (not from the plan alone): a new `docs/AI_ANALYST.md`, the THREAT_MODEL prompt-injection section, and updates to ARCHITECTURE, DATABASE, API, DEPLOYMENT, ROADMAP, PRD and README. It runs in parallel with phases 8 and 9. UI screenshots and wording that depend on phase 8 / 9 are described generically, and phase 11 fixes the final wording.

**Owns:** `docs/AI_ANALYST.md` (new), `docs/{ARCHITECTURE,DATABASE,API,THREAT_MODEL,DEPLOYMENT,ROADMAP,PRD}.md`, `README.md`. `docs/TESTING.md` and `.env.example` are **not** owned here: phase 11 owns TESTING, and phase 1 owns `.env.example`.

## Requirements
- **`docs/AI_ANALYST.md`:**
  1. **What it is and is not:**
     - observations explained with citations, never verdicts;
     - no tools, no commands, no host access, never auto-acted on;
     - opt-in per org.
  2. **Flow diagram:** API builds and freezes → analyst-worker → provider → verifier → UI.
  3. **Providers table:** models (verified / unverified, as found in phase 3), prices with `price_version`, SDK versions (`anthropic` on `httpx2`), call shape (streamed structured outputs, no temperature, adaptive thinking, effort, caching, timeouts and the per-run call cap), refusals as final (no fallbacks in M5), the Gemini billing gate and paid-tier attestation, mock / ai-mock markers, the platform dev key overlay and its daily ceiling.
  4. **Tasks:** each task and its context core, the caps and the incident map-reduce with digest reuse.
  5. **Context rules:**
     - labels, selection order, field allowlists, never-selected fields, the token estimate vs `count_tokens`;
     - truncation records;
     - sanitization, defanging, the spotlighting / delimiter / canary scheme;
     - the `context_sha256` determinism.
  6. **Privacy:**
     - the opt-in and acknowledgements;
     - pseudonymization rules and limits, and the org CIDRs and suffixes;
     - the inclusion toggles;
     - what is stored (frozen context, pseudonym map) and who can see it;
     - the preview and the context viewer;
     - provider retention (Anthropic standard, no training by default, ZDR by agreement only; Covered Models excluded; Gemini paid-tier only).
  7. **Output contract:** sections, the schema `ai.v1`, `PROMPT_VERSION`.
  8. **Verification:** citation statuses and reason codes, claim support rules, ATT&CK checks, timeline ts sourcing, flags, metrics.
  9. **Run lifecycle:** statuses and every error code with its cause and the user-visible message; waiting/resume; deadline; reaper.
  10. **Cost controls:** budgets, ceilings, limiter, per-user and org caps, cost estimate semantics.
  11. **Keys:** sealing domain `cyberlab.ai.v1`, write-only, rotation runbook (gen with `--add`, active kid, lazy re-seal by the analyst on the next use, then retire the old private kid), separation from TI keys.
  12. **Evaluation:** cases, golden files, injection payloads P1–P8, providers, metrics and floors, the live mode, where results are recorded.
  13. **Limitations:** model quality, refusals, pseudonymization coverage, integrity attacks only detected, unverified model ids, no retention policy.
- **THREAT_MODEL.md:**
  - add the asset "investigation content disclosed to an AI provider" and trust boundary 8, "analyst-worker ↔ LLM provider";
  - new **M5: AI analyst and prompt injection** section with a STRIDE / OWASP-LLM table (each row: mitigation, tested by, with test names from the merged code):
    - indirect prompt injection from captures, samples, TI and case text (LLM01);
    - insecure output handling: XSS, markdown links, exfiltration links (LLM05);
    - excessive agency (LLM06): none, because there are no tools and no auto-action;
    - fabricated or out-of-scope citations;
    - cross-tenant leakage through context or citations;
    - system prompt and canary leakage (LLM07);
    - sensitive information disclosure to the provider (LLM02);
    - cost DoS and unbounded consumption (LLM10);
    - key theft (AI seal domain, role separation from TI);
    - a compromised worker; the platform key in prod; mock in prod; Gemini free-tier training (operator flag plus org attestation); refusals;
    - citation forgery by trivial or unanchored quotes (RT1); untrusted text outside the evidence block (RT4); pseudonym spoofing (RT15).
  - **Residuals:**
    - integrity attacks are detected, not prevented;
    - public IOCs and file facts are disclosed;
    - pattern-based pseudonymization;
    - unrestricted egress and the app DB role of the analyst-worker;
    - the Gemini paid-tier attestation is not verifiable;
    - citation anchoring is heuristic;
    - unverified model ids;
    - no retention or purge;
    - no TLP flag.
- **ARCHITECTURE.md:** an analyst-worker section and diagram (networks: `enrich` + `egress`), the network table row, the module list (`modules/ai/`), the web pages.
- **DATABASE.md:** the 0011 tables, constraints, triggers and grants; the append-only list; the RLS index pattern.
- **API.md:** every `/ai/*` route with permissions, error codes, limits; the new analyses filter, investigation timeline and `ref` filters.
- **DEPLOYMENT.md:** AI seal keys (dev pair, prod keygen, `chown 10001`, rotation), the analyst-worker prod override and replicas, `BROKER_ANALYST_PASSWORD`, `GEMINI_BILLING_ENABLED`, the platform-key overlay (dev only), ai-mock profiles, the egress table update.
- **ROADMAP.md:** M5 done with scope and deferrals (Out of scope list); M6 notes (reports embed `ai_outputs` via `ai_context_refs`).
- **PRD.md / README.md:** feature summary, opt-in and privacy note, provider keys are BYOK.

## Implementation Steps
1. Read the merged group-B code and the phase notes; collect the exact routes, codes, settings, test names and model verification results.
2. Write `AI_ANALYST.md`.
3. THREAT_MODEL section and residuals.
4. The other doc updates.
5. Cross-check every test name and route cited in the docs against the code (a grep script in the phase notes).

## Success Criteria
- [x] `docs/AI_ANALYST.md` covers sections 1–13 and matches the code (routes, codes, settings, defaults). — 0f776a3 (355 lines: what it is, pipeline, providers, tasks, context rules, privacy, output contract, citation verification, run lifecycle, budgets, keys, evaluation, limitations), corrected in 6b52742 (ai-mock markers, reveal permission, `_refund_call`, per-minute limits). Check on 2026-11-06: all 12 `/ai/*` routes in `router_*.py` appear in docs/API.md, and all 132 test names cited in AI_ANALYST.md and the THREAT_MODEL M5 section exist in the test trees. The phase-11 reviewer pass is still open.
- [x] THREAT_MODEL has the M5 section with tests named per row and the residuals. — docs/THREAT_MODEL.md: the (M5) asset, trust boundary 8, "M5: AI analyst and prompt injection" with 24 rows naming their tests, and 13 accepted residuals (0f776a3, 6b52742).
- [x] ARCHITECTURE, DATABASE, API, DEPLOYMENT, ROADMAP, PRD and README are updated; no doc claims an unverified model id or price as verified. — all seven were updated in 0f776a3; AI_ANALYST.md marks every vendor model "Verified: **no**", and THREAT_MODEL lists "Unverified model ids and prices" as a residual.

## Risk Assessment
- **Docs drifting from phase 8 / 9 wording.** Phase 11 reconciles the UI strings and screenshots.
- **Overstating protection.** The prompt-injection text must say that integrity attacks are bounded and detected, not prevented.

## Implementation Notes (2026-11-06)
- **Commits:**
  - 0f776a3: 11 files, +652;
  - 6b52742: corrections to AI_ANALYST, API, TESTING and THREAT_MODEL after the phase-11 fixes.
- **AI_ANALYST.md:**
  - It follows the plan's sections 1–13.
  - It records: the providers table (SDK versions, call shapes, `Verified: no`); the tasks and caps; labels, allowlists and the transform order; privacy and pseudonymization coverage; the `ai.v1` contract; the citation and claim rules with every reason code; the error-code table; budgets and ceilings; the rotation runbook; the evaluation results; the limitations.
- **THREAT_MODEL.md, the M5 table (24 rows):**
  - the OWASP-LLM rows: LLM01, LLM02, LLM05, LLM06, LLM07, LLM10;
  - the red-team rows: RT1 (citation forgery), RT4 (text outside the block), RT15 (pseudonym spoofing), RT5 (Gemini free tier), RT7 (long calls), RT17 (platform key);
  - key theft, a compromised worker, forged messages, key leakage, adapter allowlist, mock in prod, refusals.
- **THREAT_MODEL.md, the residuals (13):**
  - integrity attacks are detected, not prevented; anchoring is heuristic;
  - public IOCs and file facts are disclosed; pseudonymization is pattern-based;
  - unrestricted egress and the full app DB role (RT26);
  - the Gemini attestation cannot be verified; model ids and prices are unverified;
  - no retention or purge (RT28); no TLP flag; provider retention;
  - a member can spend the org's budget; the AI private keys are in a host file; there is no batch re-seal tool.
- **Wording rule kept:** prompt injection is "bounded and detected, not prevented" (AI_ANALYST "Prompt structure and injection defenses", TESTING, THREAT_MODEL).
- **Other docs:**
  - ARCHITECTURE: the analyst-worker on `enrich` + `egress`;
  - DATABASE: the 0011 tables, triggers and grants;
  - API: every `/ai/*` route with permissions, error codes and limits, plus the timeline, analyses and `ref` filters;
  - DEPLOYMENT: AI seal keys, the prod override with 2 replicas, `BROKER_ANALYST_PASSWORD`, `GEMINI_BILLING_ENABLED`, the platform-key overlay;
  - ROADMAP: M5 ✅, plus the M6 note that reports embed `ai_outputs` through `ai_context_refs` / `ai_citations`;
  - PRD and README: the feature, the opt-in, BYOK.
- **Metric provenance:** the docs say "offline" and "live: none recorded" (TESTING: "AI evidence citation accuracy (§14) | ✅ offline … ⏳ live: none recorded").
- **Cross-check (implementation step 5), run 2026-11-06:**
  - `grep -oE 'test_[a-z0-9_]+'` over docs/AI_ANALYST.md and lines 161–215 of docs/THREAT_MODEL.md finds 132 unique names;
  - each one was searched in `apps/api/tests`, `packages/py-worker-kit/tests` and `apps/workers/*/tests`: 0 missing;
  - the route list of `apps/api/app/modules/ai/router_*.py` (12 routes) matches docs/API.md.
- **Deviation:** 0f776a3 also edited `docs/TESTING.md` (owned by phase 11) and `.env.example` (owned by phase 1): the M5 suites table and the `AI_ANTHROPIC_EFFORT` comment. Phase 11 later corrected TESTING.
- **Open:** the phase-11 reviewer pass and `pnpm verify:prod` (pending gate) may still require doc edits.
