---
phase: 10
title: "Docs and threat model"
status: pending
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
- [ ] `docs/AI_ANALYST.md` covers sections 1–13 and matches the code (routes, codes, settings, defaults).
- [ ] THREAT_MODEL has the M5 section with tests named per row and the residuals.
- [ ] ARCHITECTURE, DATABASE, API, DEPLOYMENT, ROADMAP, PRD and README are updated; no doc claims an unverified model id or price as verified.

## Risk Assessment
- **Docs drifting from phase 8 / 9 wording.** Phase 11 reconciles the UI strings and screenshots.
- **Overstating protection.** The prompt-injection text must say that integrity attacks are bounded and detected, not prevented.
