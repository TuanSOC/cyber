---
phase: 9
title: "AI settings and providers frontend"
status: completed
priority: P2
effort: "5h"
dependencies: [7]
---

# Phase 9: AI settings and providers frontend (group C, 3b)

## Overview
The admin side on the Integrations page:
- an "AI providers" section (Anthropic, Gemini, Mock in dev) with write-only keys, a terms acknowledgement, a model choice from the allowlist, verify status and privacy notices;
- an "AI analysis" settings card: org opt-in with privacy acknowledgement, pseudonymization and the internal CIDR and suffix lists, inclusion toggles, budgets within the ceilings, and today's usage.

It starts after the group-B merge and the regenerated contracts, in parallel with phases 8 and 10.

**Owns:**
- `apps/web/lib/ai-settings.ts` (+ `ai-settings.test.ts`), `lib/use-ai-settings.ts`;
- `components/ai-settings/**` (`ai-provider-card.tsx`, `ai-terms-ack.tsx`, `ai-org-settings-card.tsx`, `ai-usage.tsx`);
- `app/(app)/o/[orgId]/settings/integrations/page.tsx`.

It does not edit `components/ti/**`. Where the TI `integration-card.tsx` / `terms-ack.tsx` patterns fit, copy them into `ai-settings/` rather than generalizing shared TI files (file ownership).

## Requirements
- **Page layout:** the Integrations page gets two headed sections, "Threat intelligence providers" (existing, unchanged) and "AI analysis". The nav summary text for Integrations is updated by phase 8 (`nav.ts` owner) if needed; this phase only asks for it.
- **AI analysis card** (`GET/PUT …/ai/settings`; admins edit, others read):
  - **Enable AI:**
    - off by default;
    - turning it on opens a dialog with the privacy notice: which data categories leave (finding text, IPs, domains, URLs without query values, file facts, TI summaries if enabled, case text if enabled), that internal names are pseudonymized when the toggle is on, and that the provider's terms apply. Confirmation sends `acknowledge_privacy`.
    - The acknowledgement time and person are shown.
  - **Toggles:** pseudonymize internal names (on), include strings (off), include TI results (on), include case title/description (off). There is no refusal-fallback toggle (RT10).
  - **Re-acknowledgement (RT22):** turning strings or case text on, or pseudonymization off, re-opens the privacy dialog and sends `acknowledge_privacy`; `privacy_not_acknowledged` is shown inline.
  - **Lists:** internal CIDRs and suffixes as tag inputs, validated client-side (CIDR / domain-suffix syntax) with server errors shown.
  - **Budgets:** daily tokens and per-run cap, showing the ceilings; a 422 `budget_above_ceiling` is shown inline.
  - **Usage today** (`GET …/ai/usage`): tokens and estimated cost per provider vs the budget.
- **AI provider cards** (`GET/PUT/DELETE …/ai/providers…`):
  - label, ToS note, privacy note;
  - **Gemini:** when unavailable for `gemini_billing_required`, a prominent explanation ("the free tier may use prompts for training and human review; an operator must enable billing and set `GEMINI_BILLING_ENABLED`"), and the controls are disabled. When available, the first enable also needs the checkbox "This key belongs to a Google Cloud project with billing enabled (paid tier)" (`acknowledge_paid_tier`, RT5);
  - **Mock:** shown only when available (dev / test);
  - **Key field:** write-only (password input, never prefilled), shows `configured · …last4`, Replace and Remove (confirm dialog);
  - **First enable:** the terms acknowledgement checkbox (`acknowledge_terms`);
  - model select from `models` (unverified ids marked "unverified"), prices per MTok;
  - verify status badge with `last_error_code` mapped to text, and a Verify button (202, poll);
  - "Platform dev key in use" badge when `platform_key`.
- **Error mapping:** `terms_not_acknowledged`, `paid_tier_not_acknowledged`, `privacy_not_acknowledged`, `model_not_allowed`, `provider_unavailable`, `budget_above_ceiling`, 403 for non-admins (read-only rendering instead).
- **Never show a key:** after a PUT the input clears; no key value is put in query caches, logs or toasts (test).

## Implementation Steps
1. `lib/ai-settings.ts` (types, validators for CIDR and suffix, error map) with unit tests.
2. Provider card, terms acknowledgement, settings card, usage component; wire them into the Integrations page.
3. Component tests: the key never rendered back; terms and privacy acknowledgement flows; Gemini disabled state; read-only for analysts and viewers; budget errors.

## Success Criteria
- [x] An admin can enable AI (with the acknowledgement), configure a provider key (write-only) with terms, pick a model and verify; others see read-only state. — `components/ai-settings/ai-settings.test.tsx` (AiPrivacyAckForm "blocks enabling until the privacy notice is acknowledged", AiTermsAckForm "blocks enabling until the terms are acknowledged", AiProviderCard "is read-only without integrations.manage", AiOrgSettingsPanel "is read-only for analysts and viewers"); `lib/ai-settings.test.ts` "acknowledgements: terms on first enable, paid tier only for gemini", "state and enable rules"; the server side in `test_ai_api_providers.py` and `test_ai_api_settings.py` (5e9b97e, 83f24a1). The browser flow is in the dev e2e (pending gate).
- [x] Gemini without billing and mock in prod are visibly unavailable with reasons. — "Gemini without billing: prominent explanation and no controls, even for admins"; `lib/ai-settings.test.ts` "explains gemini billing and marks unverified models", "shows the mock only when available" (5e9b97e). Deviation: in prod the mock card is hidden, not shown disabled with a reason; the catalog says `prod_mock` and the PUT answers 422. The prod e2e assertion is pending gate.
- [x] Component tests prove that no key value is rendered or cached after save. — "shows the key only as configured · ••••last4 and never renders a key value", "uses a write-only, empty password input with autocomplete off", "does not pre-fill the key field of an unconfigured provider"; `storeAiKey` "sends the key once, clears the input and keeps it out of every cache and log", "clears the input when the request fails, and throws the typed error", "clears the input on a network error"; "never shows server validation text for the key form" (5e9b97e).

## Risk Assessment
- **Duplicated card code with TI.** Accepted for file ownership; a later refactor can extract shared parts.
- **Admins misunderstanding pseudonymization coverage.** The card text lists exactly what is detected and asks for org CIDRs and suffixes.

## Implementation Notes (2026-11-06)
- **Commits:**
  - 5e9b97e (shared with phase 8): `lib/ai-settings.ts`, `lib/use-ai-settings.ts`, `components/ai-settings/{ai-provider-card,ai-terms-ack,ai-privacy-ack,ai-org-settings-card,ai-usage}.tsx`, and the Integrations page split into "Threat intelligence providers" and "AI analysis";
  - 6b52742: the per-minute limit form on the provider card.
- **Provider card:**
  - label, ToS and privacy notes;
  - key status `configured · ••••last4`, Replace and Remove (with a confirm dialog);
  - model select with prices per MTok, and "unverified" marks;
  - verify badge with `last_error_code` mapped to text;
  - a "Platform dev key" badge ("maps the last error code and shows the platform dev key badge").
- **Acknowledgements:**
  - terms on the first enable; Gemini also needs the paid-tier attestation (RT5);
  - the form asks only for what is still missing ("asks only for what is still missing").
- **Privacy dialog:**
  - it lists the categories that would leave under the next settings ("lists the categories that leave under the next settings");
  - `needsPrivacyAck` predicts a re-ask for AI on, strings on, case text on, and pseudonymization off.
  - **Gap:** the API (phase-7 review) also asks again when `include_ti` is turned on or a CIDR or suffix entry is removed. In those cases the server answers `422 privacy_not_acknowledged`, and only then does `ai-org-settings-card.tsx` reopen the dialog. That fallback has no component test, and `lib/ai-settings.test.ts` still expects `include_ti: true` to need no acknowledgement, which no longer matches the API.
- **Toggles:**
  - defaults: pseudonymize on, strings off, TI on, case text off;
  - no refusal-fallback toggle (RT10: "is off by default with the defaults for an admin; no refusal-fallback toggle");
  - "cannot turn AI on when the deployment has it off".
- **Lists:** CIDR and domain-suffix validators; pasted entries are added and deduplicated, with an error per entry ("adds pasted entries, deduplicates and reports errors").
- **Budgets and usage:**
  - budgets show the ceilings, and a value above them is blocked ("shows the ceilings and blocks a budget above them");
  - usage shows today's tokens and the ≈ cost per provider against the budget.
- **Errors:** stable codes are mapped, a 403 renders read-only, and server validation text is never shown for the key form.
- **Phase 11 (6b52742):** a per-minute request limit with its maximum, which admins may set ("shows the request limit with its maximum; admins may set their own").
- **Deviations:**
  - The card code is duplicated from TI rather than shared (accepted, for file ownership).
  - The prod mock is hidden instead of disabled.
  - The client-side re-consent rule lags the API (see the gap above).
